//! Real attestation via the Nitro Security Module device (`/dev/nsm`),
//! which exists only inside an actual running Nitro Enclave. Verified
//! against the real API surface (docs.rs + upstream source of
//! `aws-nitro-enclaves-nsm-api`), not guessed:
//! `nsm_init()` returns `-1` on a missing device rather than panicking, and
//! `nsm_process_request` degrades to `Response::Error` on a bad descriptor
//! — so this whole path fails cleanly, never crashes, when there's no real
//! hardware (e.g. WSL2, or the plain parent EC2 instance outside any
//! enclave).
//!
//! The attestation document NSM returns is a COSE_Sign1 envelope (a
//! 4-element CBOR array: protected header, unprotected header, payload,
//! signature) wrapping the CBOR-encoded `AttestationDoc`. Parsing it isn't
//! enough on its own — anyone who can intercept the vsock channel could hand
//! us a well-formed but fabricated document. `attestation-doc-validation`
//! (Evervault, MIT/Apache-2.0) closes that gap: it verifies the COSE_Sign1
//! signature and walks the certificate chain up to AWS's Nitro root CA
//! (embedded in the crate, checked via `webpki`) before handing back a
//! parsed `AttestationDoc` — so a tampered or unsigned document is rejected
//! here, not trusted.

use attestation_doc_validation::validate_and_parse_attestation_doc;
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

#[derive(Debug, thiserror::Error)]
pub enum NitroAttestationError {
    #[error("/dev/nsm is not available on this machine (not running inside a real enclave)")]
    NoDevice,
    #[error("NSM returned an error response instead of an attestation document")]
    NsmError,
    #[error("NSM response was not an Attestation variant")]
    UnexpectedResponse,
    #[error(
        "attestation document failed cryptographic validation \
         (COSE_Sign1 signature or certificate chain to the AWS Nitro root): {0}"
    )]
    Validation(#[from] attestation_doc_validation::error::AttestError),
    #[error("attestation document has no PCR0")]
    MissingPcr0,
}

/// The real-hardware facts this module can pull out of a validated NSM
/// attestation document, beyond PCR0 alone.
///
/// `timestamp_secs` and `module_id` exist specifically for TODO.md item #4:
/// `kdf_core::AttestationKey::sign_quote`'s `issued_at` parameter is
/// documented as wanting a hardware-signed timestamp rather than the
/// enclave's own self-reported clock — this is that value, actually read
/// from real hardware instead of `SystemTime::now()`. `module_id` is the
/// Nitro hypervisor's own per-enclave identifier (assigned at enclave
/// creation, not something code running inside the enclave can choose or
/// fake); comparing it across sessions may let a verifier distinguish "the
/// same still-running enclave asking again" from "a genuinely new enclave
/// instance" in a way a timestamp alone cannot — see TODO.md item #4's
/// 2026-09-09 refinement for the caveats (AWS does not appear to publicly
/// document a formal per-launch-uniqueness guarantee for this field; treat
/// it as a promising lead to confirm with AWS, not yet a relied-upon proof).
#[derive(Debug)]
pub struct AttestationFacts {
    pub pcr0: Vec<u8>,
    /// PCR8, when present: the SHA-384 hash of the enclave image file's
    /// signing certificate -- a "who signed this build" fact, distinct from
    /// PCR0's "what code is this" fact. `None` when the document has no
    /// PCR8 entry at all (an EIF built without `--signing-certificate`, the
    /// common case for a dev/CI build that isn't yet part of a signed
    /// release pipeline -- not an error, just "not present here").
    pub pcr8: Option<Vec<u8>>,
    /// NSM's own `timestamp` field, converted from the wire format
    /// (milliseconds since the Unix epoch, per the NSM API's CDDL schema)
    /// to whole seconds — `kdf_core`'s `issued_at`/`verify_freshness` are
    /// both modeled in seconds, and mixing units here would silently make
    /// every `max_age_seconds` policy meaningless.
    pub timestamp_secs: u64,
    pub module_id: String,
    /// Echoes back the `nonce` this document was requested with, if any --
    /// added 2026-09-30 after a real external review pointed out that
    /// `fetch_raw_document`'s original hardcoded `nonce: None` meant this
    /// crate's own CLI had no way to prove a fetched document was fresh
    /// rather than replayed. `None` when no nonce was requested (the
    /// original, still-default behavior via `fetch_raw_document`) --
    /// `fetch_raw_document_with_nonce` is the new entry point that sets
    /// this.
    pub nonce: Option<Vec<u8>>,
}

/// Fetches a fresh, RAW attestation document from the real NSM device --
/// deliberately not verified here. Split out from `fetch_attestation_facts`
/// (2026-09-14, TODO.md item #4's vsock-relay refinement) so the enclave
/// side of that relay can obtain these bytes to forward over vsock without
/// also needing to verify them locally first (verification happens on the
/// receiving end -- see `verify_and_parse`). Only meaningful inside a real
/// running enclave (`/dev/nsm` present); `NoDevice` off real hardware, same
/// as before.
///
/// Requests no nonce (matches this function's original, still-unchanged
/// signature and behavior, so every existing caller -- `tee-service`'s own
/// self-report, both examples -- is unaffected). Use
/// `fetch_raw_document_with_nonce` for a freshness-provable fetch.
pub fn fetch_raw_document() -> Result<Vec<u8>, NitroAttestationError> {
    fetch_raw_document_with_optional_nonce(None)
}

/// Same as `fetch_raw_document`, but binds the document to a caller-chosen
/// nonce (up to 512 bytes per the NSM API) -- NSM signs the nonce INTO the
/// document, so a verifier who generated that nonce themselves and checks
/// it comes back unchanged (`AttestationFacts::nonce`) has real, hardware-
/// backed proof this exact document was produced after the nonce existed,
/// not replayed from an earlier, possibly-stale fetch.
pub fn fetch_raw_document_with_nonce(nonce: &[u8]) -> Result<Vec<u8>, NitroAttestationError> {
    fetch_raw_document_with_optional_nonce(Some(nonce))
}

fn fetch_raw_document_with_optional_nonce(nonce: Option<&[u8]>) -> Result<Vec<u8>, NitroAttestationError> {
    let fd = nsm_init();
    if fd < 0 {
        return Err(NitroAttestationError::NoDevice);
    }

    let response = nsm_process_request(
        fd,
        Request::Attestation {
            user_data: None,
            nonce: nonce.map(|n| n.to_vec().into()),
            public_key: None,
        },
    );
    nsm_exit(fd);

    match response {
        Response::Attestation { document } => Ok(document),
        Response::Error(_) => Err(NitroAttestationError::NsmError),
        _ => Err(NitroAttestationError::UnexpectedResponse),
    }
}

/// Cryptographically verifies a raw attestation document (COSE_Sign1
/// signature + certificate chain to AWS's Nitro root) and extracts the
/// facts this module cares about. Deliberately takes raw bytes rather than
/// only being reachable via `/dev/nsm` -- this is the reusable half of what
/// `fetch_attestation_facts` used to do all in one step, split out
/// specifically so a PARENT instance (which has no `/dev/nsm` of its own)
/// can independently re-verify bytes an enclave forwarded to it over vsock,
/// rather than trusting the enclave's own unverified claim about what a
/// document says. This is what closes TODO.md item #4's corrected
/// conclusion: `nitro-cli`'s own `EnclaveID` is forgeable by a compromised
/// host, but a `module_id` that only comes out of THIS function -- which
/// demands an actual valid hardware signature -- is not.
pub fn verify_and_parse(document: &[u8]) -> Result<AttestationFacts, NitroAttestationError> {
    let doc: AttestationDoc = validate_and_parse_attestation_doc(document)?;

    let pcr0 = doc
        .pcrs
        .get(&0)
        .map(|pcr0| pcr0.to_vec())
        .ok_or(NitroAttestationError::MissingPcr0)?;
    let pcr8 = doc.pcrs.get(&8).map(|pcr8| pcr8.to_vec());

    Ok(AttestationFacts {
        pcr0,
        pcr8,
        timestamp_secs: doc.timestamp / 1000,
        module_id: doc.module_id,
        nonce: doc.nonce.map(|n| n.to_vec()),
    })
}

/// Pure decision for TODO.md item #4's vsock relay: given whatever
/// module_id was previously recorded (`None` on a first-ever check) and a
/// freshly, INDEPENDENTLY VERIFIED one (i.e. already passed through
/// `verify_and_parse` -- this function has no opinion on trust, only on
/// novelty), decide whether this counts as confirmed progress. Kept
/// separate from the I/O around it (reading/writing the state file, the
/// vsock exchange itself) specifically so this decision is unit-testable
/// without any hardware or network -- mirrors `tee-service::state::
/// resume_state`'s same "pure decision, I/O stays at the call site" shape.
pub fn is_genuinely_new_module_id(previous: Option<&str>, new: &str) -> bool {
    previous != Some(new)
}

/// Fetches a fresh attestation document from the real NSM device and
/// cryptographically verifies it (COSE_Sign1 signature + certificate chain
/// to AWS's Nitro root). Convenience wrapper over `fetch_raw_document` +
/// `verify_and_parse` for the common in-enclave case (fetch and trust your
/// own local hardware in one step) -- unchanged behavior/signature from
/// before this module's split, so every existing caller/test is unaffected.
pub fn fetch_attestation_facts() -> Result<AttestationFacts, NitroAttestationError> {
    verify_and_parse(&fetch_raw_document()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `fetch_attestation_facts` only succeeds inside a real, running Nitro
    // Enclave (`/dev/nsm` present) -- these are `#[ignore]`d so a plain
    // `cargo test -p tee-adapter --features nitro` (WSL2, CI, a bare EC2
    // instance) never fails on missing hardware. Run once, right before
    // tearing the enclave/instance back down, via
    // `scripts/nitro-hardware-test.sh nitro::`.
    #[test]
    #[ignore]
    fn fetch_attestation_facts_succeeds_on_real_hardware() {
        let facts = fetch_attestation_facts()
            .expect("NSM attestation should succeed inside a real, running enclave");

        // Nitro PCRs are SHA384 digests (48 bytes) -- see fold_to_32's doc
        // comment in mod.rs. A different length here means either a parsing
        // regression or AWS having changed the PCR digest algorithm.
        assert_eq!(facts.pcr0.len(), 48, "PCR0 should be a 48-byte SHA384 digest");
        assert!(!facts.module_id.is_empty(), "module_id must be populated by NSM");

        // A loose bound on purpose, not a tight one -- it just needs to
        // reject both an unset (0) timestamp and the exact regression this
        // field already had once (NSM's wire timestamp is milliseconds; see
        // TODO.md item #4, 2026-09-09), which would land ~1000x too large.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            facts.timestamp_secs > now.saturating_sub(300) && facts.timestamp_secs <= now + 5,
            "timestamp_secs ({}) should be within a few minutes of wall-clock now ({now})",
            facts.timestamp_secs,
        );
    }

    #[test]
    #[ignore]
    fn pcr0_and_module_id_are_stable_across_repeated_calls() {
        // PCR0 measures the enclave image itself and module_id is assigned
        // once at enclave creation -- neither should change between two
        // calls against the same still-running enclave. Only the timestamp
        // is expected to move, and only forward.
        let first = fetch_attestation_facts().expect("first fetch");
        let second = fetch_attestation_facts().expect("second fetch");

        assert_eq!(first.pcr0, second.pcr0, "PCR0 must not change within one enclave's lifetime");
        assert_eq!(
            first.module_id, second.module_id,
            "module_id must not change within one enclave's lifetime"
        );
        assert!(
            second.timestamp_secs >= first.timestamp_secs,
            "timestamp must not go backwards between two calls moments apart"
        );
    }

    // The flip side of the two tests above, and NOT hardware-dependent: off
    // real hardware (WSL2, a bare EC2 instance, CI) this must fail cleanly
    // with the documented error, never panic. Not `#[ignore]`d -- it costs
    // nothing and runs on every `cargo test -p tee-adapter --features nitro`.
    #[test]
    fn fails_cleanly_without_the_nsm_device() {
        match fetch_attestation_facts() {
            Err(NitroAttestationError::NoDevice) => {}
            other => panic!("expected NoDevice off real Nitro hardware, got {other:?}"),
        }
    }

    // verify_and_parse is pure (no /dev/nsm access) -- these run everywhere,
    // no hardware or #[ignore] gate needed, and exercise exactly the path
    // the vsock relay's host side depends on: a corrupted, forged, or
    // truncated document (the shape a compromised or merely buggy peer
    // could send) must be rejected cleanly, never panic and never be
    // silently accepted.
    #[test]
    fn verify_and_parse_rejects_garbage_bytes_without_panicking() {
        let err = verify_and_parse(b"not a valid attestation document").unwrap_err();
        assert!(matches!(err, NitroAttestationError::Validation(_)));
    }

    #[test]
    fn verify_and_parse_rejects_empty_bytes_without_panicking() {
        let err = verify_and_parse(&[]).unwrap_err();
        assert!(matches!(err, NitroAttestationError::Validation(_)));
    }

    #[test]
    fn first_ever_check_with_no_previous_record_counts_as_new() {
        assert!(is_genuinely_new_module_id(None, "i-abc-enc123"));
    }

    #[test]
    fn a_different_module_id_counts_as_new() {
        assert!(is_genuinely_new_module_id(Some("i-abc-enc111"), "i-abc-enc222"));
    }

    #[test]
    fn the_same_module_id_as_last_time_does_not_count_as_new() {
        // The actual failure shape TODO.md item #4 exists to catch: a
        // genuinely, cryptographically verified module_id that just happens
        // to be identical to the last recorded one -- must not be treated
        // as progress.
        assert!(!is_genuinely_new_module_id(Some("i-abc-enc111"), "i-abc-enc111"));
    }
}
