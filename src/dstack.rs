//! Real attestation via dstack's guest-agent socket (`/var/run/dstack.sock`)
//! -- the Intel TDX equivalent of Nitro's `/dev/nsm` device. Exists only
//! inside a real dstack-managed TDX confidential VM (e.g. a Phala Cloud
//! CVM); TODO.md item #11 has the real deployment this was verified
//! against (`tachpawl-tee-service` running on Phala Cloud).
//!
//! Verified against `dstack-sdk` 0.1.3's real published source (docs.rs,
//! not guessed): `DstackClient::get_quote(report_data)` is a real async
//! HTTP-over-Unix-socket call (via `reqwest` + `http-client-unix-domain-
//! socket`, both real async I/O, not a blocking shim), returning a
//! `GetQuoteResponse` whose `quote`/`event_log` fields are hex-encoded
//! strings -- confirmed directly from the crate's own `decode_quote()`
//! helper, which calls `hex::decode`, not assumed from secondary docs.
//!
//! Split the same way `nitro.rs` is, for the same reason: `fetch_raw_quote`
//! returns unverified bytes so a caller could forward them elsewhere before
//! trusting them (mirrors `nitro::fetch_raw_document`). **A real, meaningful
//! difference from Nitro, stated plainly**: Nitro verification is fully
//! offline (`attestation-doc-validation` embeds AWS's own root CA), but a
//! real DCAP quote's certificate chain needs Intel's own collateral (PCK
//! certs, TCB info, CRLs) fetched from a PCCS -- so `verify_and_parse` here
//! is unavoidably async/networked, not the pure function `nitro::
//! verify_and_parse` is. Verified against `dcap-qvl` 0.6.3's real published
//! source (github.com/Phala-Network/dcap-qvl, tag v0.6.3, not a README
//! paraphrase): `dcap_qvl::verify::verify(quote, &collateral, now_secs)` is
//! itself a pure/offline function (no `.await` anywhere in its real
//! implementation) -- all network I/O is confined to the separate
//! `CollateralClient::fetch` step. The PCCS collateral is served from
//! Phala's own caching endpoint (`PHALA_PCCS_URL`, the crate's documented
//! default) rather than Intel's directly -- this doesn't weaken trust: a
//! PCCS only ever caches Intel-signed certificates/TCB info, and
//! `dcap_qvl::verify` independently checks that signature chain up to
//! Intel's real root CA regardless of which caching proxy served the bytes.
//!
//! Not wired into `resolve_measurement()`'s fallback chain yet (mirrors
//! `sgx.rs`'s own "not wired in yet" convention) -- folding `mr_td` into a
//! `MeasurementValue` there is the next step, not done in this pass.

use dstack_sdk::dstack_client::DstackClient;

#[derive(Debug, thiserror::Error)]
pub enum DstackAttestationError {
    #[error("report_data must be 1-64 bytes (the TDX quote's REPORTDATA field), got {0}")]
    InvalidReportData(usize),
    #[error("dstack guest agent socket unavailable or request failed: {0}")]
    RequestFailed(String),
    #[error("quote field was not valid hex: {0}")]
    MalformedQuoteHex(#[from] hex::FromHexError),
    #[error("failed to fetch DCAP collateral (Intel PCK certs/TCB info) from the PCCS: {0}")]
    CollateralFetchFailed(String),
    #[error("quote verification failed (certificate chain, signature, or TCB status): {0}")]
    VerificationFailed(String),
    #[error("verified report was not a TDX report (mismatched attestation type)")]
    NotATdxReport,
    #[error("quote layout is inconsistent with its own header: {0}")]
    MalformedQuoteLayout(#[from] QuoteLayoutError),
}

/// Why `td_id_from_quote` could not read a quote's layout. Only ever about
/// the byte layout, never about trust: the parser checks no signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuoteLayoutError {
    #[error("quote is {0} bytes, too short for its header and body-type fields")]
    TooShortForHeader(usize),
    #[error("quote v5 body type 4 declares a {declared}-byte body but only {available} bytes follow")]
    TruncatedBody { declared: usize, available: usize },
    #[error("quote v5 body type 4 declares a {0}-byte body, shorter than the field td_id ends at")]
    BodyTooShortForTdId(usize),
}

/// TDX's per-launch identifier (`td_id`, Intel's `TDID256`): 32 random bytes
/// the TDX Module generates on every TD launch, regenerated on relaunch and
/// preserved across TD-preserving updates and migration -- the TDX analog of
/// Nitro's `module_id` for restart detection. Present only in a quote v5 whose
/// body type is 4 (TD report "1.5ex"); all-zero when the host did not enable it.
pub type TdId = [u8; 32];

// Offsets from Intel's own `sgx_quote_5.h` (intel/confidential-computing.sgx.sdk,
// common/inc), read 2026-10-05: `sgx_quote5_t` is a 48-byte header, a `u16`
// body type at 48, a `u32` body size at 50 and the body at 54; in
// `sgx_report2_body_v1_5_ex_t` the `u8 vmid` is at 648 and `td_id` at 649..681.
const QUOTE_HEADER_LEN: usize = 48;
const QUOTE_V5_BODY_OFFSET: usize = 54;
const QUOTE_V5_BODY_TYPE_TD15_EX: u16 = 4;
const TD15_EX_TD_ID_OFFSET: usize = 649;
const TD15_EX_TD_ID_END: usize = TD15_EX_TD_ID_OFFSET + 32;

/// Reads `td_id` from a raw quote's bytes. **Checks no signature**: the result
/// means something only for a quote whose signature has been verified, as
/// `verify_and_parse_with_pccs` does before calling this.
///
/// `Ok(None)` for every quote that has no such field (version 4, or version 5
/// with body type 1-3) and for an all-zero `td_id`, which is what a TD reports
/// when the host has not set `TDX_FEATURES0.TDID_VMID_REPORTING` -- no
/// upstream KVM/QEMU does today (Intel's moderator on the community forum,
/// 2026-09-28; on 2026-10-05 he confirmed a self-built v7.2 kernel setting the
/// bits during `TDH.SYS.CONFIG` yields a non-zero value). So `None` must be
/// read as "this platform gives no restart signal", never as "no restart".
pub fn td_id_from_quote(quote: &[u8]) -> Result<Option<TdId>, QuoteLayoutError> {
    if quote.len() < QUOTE_V5_BODY_OFFSET {
        return Err(QuoteLayoutError::TooShortForHeader(quote.len()));
    }
    let version = u16::from_le_bytes([quote[0], quote[1]]);
    let body_type = u16::from_le_bytes([quote[QUOTE_HEADER_LEN], quote[QUOTE_HEADER_LEN + 1]]);
    if version != 5 || body_type != QUOTE_V5_BODY_TYPE_TD15_EX {
        return Ok(None);
    }
    let size_bytes: [u8; 4] = quote[50..54].try_into().expect("slice of length 4");
    let declared = u32::from_le_bytes(size_bytes) as usize;
    let available = quote.len() - QUOTE_V5_BODY_OFFSET;
    if declared > available {
        return Err(QuoteLayoutError::TruncatedBody { declared, available });
    }
    if declared < TD15_EX_TD_ID_END {
        return Err(QuoteLayoutError::BodyTooShortForTdId(declared));
    }
    let start = QUOTE_V5_BODY_OFFSET + TD15_EX_TD_ID_OFFSET;
    let td_id: TdId = quote[start..start + 32].try_into().expect("slice of length 32");
    Ok(if td_id == [0u8; 32] { None } else { Some(td_id) })
}

/// The real-hardware facts a validated TDX quote yields, mirroring what
/// `nitro::AttestationFacts` gives for a Nitro attestation document --
/// `mr_td` (MRTD, the TD's initial/static image measurement) is the TDX
/// analog of Nitro's PCR0, both fixed per build. RTMR0-3 (runtime/boot-
/// event extensions -- kernel, initrd, cmdline, and dstack's own
/// application-level extensions) are exposed too but deliberately NOT
/// folded into a `MeasurementValue` in this pass, the same "simplest
/// correct thing first" scope `resolve_measurement()` itself already
/// documents choosing for PCR0-only on Nitro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationFacts {
    pub mr_td: [u8; 48],
    pub rt_mr0: [u8; 48],
    pub rt_mr1: [u8; 48],
    pub rt_mr2: [u8; 48],
    pub rt_mr3: [u8; 48],
    /// TDX's software-defined identity fields (Intel's real names:
    /// MRCONFIGID/MROWNER/MROWNERCONFIG) -- raised while investigating a
    /// TODO.md item #4-style restart-detection signal for TDX (a real
    /// Intel-engineer forum reply named these as the SGX-KSS-style
    /// equivalent). **Architecturally NOT settable by this crate, stated
    /// plainly**: unlike `report_data` below, these are TD-creation-time
    /// parameters set once by whoever launches the TD (dstack's own control
    /// plane), not something `fetch_raw_quote`'s guest-side `get_quote`
    /// call can influence per-request -- `tee-service` running inside the
    /// TD has no API to populate them itself. Exposed here purely to
    /// observe their REAL values on a real deployment (do they happen to be
    /// all-zero, since they're optional and nothing requires dstack to set
    /// them, or does dstack's own launch tooling put something meaningful
    /// here, e.g. a compose-file hash?) -- not yet confirmed either way.
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    /// The per-launch `td_id` (see `TdId`), or `None` where the quote carries
    /// none or an all-zero one. Always `None` today in practice: `dcap-qvl`
    /// 0.6.x verifies only body types 1-3 and rejects the type-4 body that
    /// carries the field, so a quote with a real `td_id` does not get this far
    /// until `dcap-qvl` learns that body type; this field then fills in with no
    /// further change here.
    pub td_id: Option<TdId>,
    /// The REPORTDATA field this quote was requested with -- echoing it
    /// back lets a caller confirm the quote it got verified is the one it
    /// asked for (binds a nonce/public key), the same role Nitro's own
    /// `user_data`/`public_key` request fields would play if this crate
    /// used them (it currently requests `Request::Attestation` with all
    /// three set to `None` -- see `nitro::fetch_raw_document`).
    pub report_data: [u8; 64],
    /// DCAP's own TCB trust level, e.g. "UpToDate", "OutOfDate",
    /// "ConfigurationNeeded" -- stringified from `dcap_qvl`'s own enum.
    /// **Deliberately not enforced here**: `dcap_qvl::verify` itself only
    /// hard-rejects `Revoked` (a security invariant, not a policy choice);
    /// every other status is returned as `Ok` with this field set, and
    /// deciding whether e.g. "OutOfDate" is acceptable is left to the
    /// caller/policy layer, mirroring how `nitro::verify_and_parse` doesn't
    /// editorialize about freshness or revocation either -- that's
    /// `kdf_core::VerificationEngine`'s job, not this module's (this crate's
    /// own `main.rs` CLI, unlike `kdf_core`, DOES enforce a default policy
    /// here -- `--allow-tcb-status`, added 2026-09-30 after a real external
    /// review found the CLI reported this field without ever gating on it).
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
    /// Whether this TD was launched with the DEBUG attribute set -- added
    /// 2026-10-01 after a real external review flagged its absence (citing
    /// `Lanetus/TTKServer#17`, a separate real implementation, as prior art
    /// for rejecting debug TDs by default). A debug TD's memory is readable
    /// by the host, so a quote from one proves nothing about confidentiality
    /// even though it still cryptographically verifies. Detected from
    /// `TDReport10::td_attributes` (`[u8; 8]`, little-endian per Intel's TDX
    /// Module ABI spec): bit 0 is `TUD.DEBUG` -- cross-checked against
    /// `Lanetus/TTKServer`'s own real, reviewed implementation
    /// (`TD_ATTRIBUTE_DEBUG: u64 = 1`, read little-endian), not derived from
    /// the spec alone.
    pub is_debug: bool,
}

/// A raw, UNVERIFIED response from dstack's guest agent. `quote` is the
/// decoded (from hex) raw TDX DCAP quote bytes -- exactly analogous to
/// `nitro::fetch_raw_document`'s return value, just not COSE_Sign1-wrapped
/// (a DCAP quote has its own binary structure, Intel's, not CBOR/COSE).
/// `event_log_json` is dstack's own JSON-array-as-string of measured boot/
/// runtime events (RTMR extensions) -- kept as an opaque string here rather
/// than parsed, since nothing in this pass consumes it yet.
#[derive(Debug)]
pub struct RawQuoteResponse {
    pub quote: Vec<u8>,
    pub event_log_json: String,
}

/// Fetches a fresh, RAW TDX quote from the real dstack guest agent --
/// deliberately not verified here, mirroring `nitro::fetch_raw_document`'s
/// same split and the same reasoning (a caller may want to forward these
/// bytes elsewhere before trusting them, rather than always verifying
/// locally). `report_data` is the TDX quote's REPORTDATA field (up to 64
/// bytes) -- the caller-supplied binding value (e.g. a nonce or an
/// application public key), analogous to SGX's REPORTDATA.
///
/// Only meaningful inside a real dstack-managed TDX VM (the guest-agent
/// socket present); fails cleanly with `RequestFailed` off real hardware
/// (e.g. plain WSL2), never panics.
pub async fn fetch_raw_quote(report_data: &[u8]) -> Result<RawQuoteResponse, DstackAttestationError> {
    if report_data.is_empty() || report_data.len() > 64 {
        return Err(DstackAttestationError::InvalidReportData(report_data.len()));
    }

    let client = DstackClient::new(None);
    let response = client
        .get_quote(report_data.to_vec())
        .await
        .map_err(|e| DstackAttestationError::RequestFailed(e.to_string()))?;

    let quote = response.decode_quote()?;

    Ok(RawQuoteResponse { quote, event_log_json: response.event_log })
}

/// Independently verifies a raw TDX DCAP quote's certificate chain to
/// Intel's real root CA and TCB status (via `dcap-qvl`, real PCCS
/// collateral -- NOT trusting `dstack-sdk`'s own parsed output), and
/// extracts the measurement registers a caller would need. Mirrors
/// `nitro::verify_and_parse`'s role exactly, with the one real difference
/// this module's own doc comment already states: this is `async`, since
/// fetching collateral is real network I/O (`verify()` itself is not).
///
/// `Revoked` TCB status is rejected as a hard error inside `dcap_qvl`
/// itself (a security invariant); every other status (`UpToDate`,
/// `OutOfDate`, etc.) is returned successfully with `tcb_status` set --
/// see `AttestationFacts::tcb_status`'s own doc comment for why that's not
/// enforced here.
pub async fn verify_and_parse(quote: &[u8]) -> Result<AttestationFacts, DstackAttestationError> {
    verify_and_parse_with_pccs(quote, dcap_qvl::collateral::PHALA_PCCS_URL).await
}

/// Same as `verify_and_parse`, but against a caller-chosen PCCS instead of
/// Phala's own. Split out (2026-09-30, real external review, see TODO.md
/// item #15) so a caller who doesn't want Phala's PCCS in their trust/
/// availability/privacy path -- e.g. Intel's own PCS, or a self-hosted
/// mirror -- isn't stuck with it: `dcap_qvl::verify` independently checks
/// the returned collateral's own signature chain up to Intel's real root CA
/// regardless of which PCCS served the bytes, so this is a choice of who to
/// ask, never a choice of who to trust.
pub async fn verify_and_parse_with_pccs(quote: &[u8], pccs_url: &str) -> Result<AttestationFacts, DstackAttestationError> {
    let collateral_client =
        dcap_qvl::collateral::CollateralClient::with_default_http(pccs_url).map_err(|e| DstackAttestationError::CollateralFetchFailed(e.to_string()))?;
    let collateral = collateral_client.fetch(quote).await.map_err(|e| DstackAttestationError::CollateralFetchFailed(e.to_string()))?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs();

    let verified =
        dcap_qvl::verify::verify(quote, &collateral, now_secs).map_err(|e| DstackAttestationError::VerificationFailed(e.to_string()))?;

    let td_report = verified.report.as_td10().ok_or(DstackAttestationError::NotATdxReport)?;
    let is_debug = td_attributes_indicate_debug_mode(td_report.td_attributes);
    let td_id = td_id_from_quote(quote)?;

    Ok(AttestationFacts {
        mr_td: td_report.mr_td,
        rt_mr0: td_report.rt_mr0,
        rt_mr1: td_report.rt_mr1,
        rt_mr2: td_report.rt_mr2,
        rt_mr3: td_report.rt_mr3,
        mr_config_id: td_report.mr_config_id,
        mr_owner: td_report.mr_owner,
        mr_owner_config: td_report.mr_owner_config,
        td_id,
        report_data: td_report.report_data,
        tcb_status: verified.status,
        advisory_ids: verified.advisory_ids,
        is_debug,
    })
}

/// Pure decision, unit-testable without a real quote: bit 0 (`TUD.DEBUG`)
/// of `TD_ATTRIBUTES`, read little-endian -- see `AttestationFacts::
/// is_debug`'s doc comment for the cross-checked source of that bit
/// position.
fn td_attributes_indicate_debug_mode(td_attributes: [u8; 8]) -> bool {
    u64::from_le_bytes(td_attributes) & 1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure input validation -- no real socket needed, runs everywhere.
    #[tokio::test]
    async fn rejects_empty_report_data_without_a_real_socket_call() {
        let err = fetch_raw_quote(&[]).await.unwrap_err();
        assert!(matches!(err, DstackAttestationError::InvalidReportData(0)));
    }

    #[tokio::test]
    async fn rejects_report_data_over_64_bytes_without_a_real_socket_call() {
        let too_long = vec![0u8; 65];
        let err = fetch_raw_quote(&too_long).await.unwrap_err();
        assert!(matches!(err, DstackAttestationError::InvalidReportData(65)));
    }

    // The exact boundary: 64 bytes is still valid (the field is "up to 64
    // bytes"), so this must pass length validation and fail only once it
    // reaches the real socket call -- catches a `>` vs `>=` off-by-one at
    // the boundary that the over/empty-length tests alone can't (found by
    // cargo-mutants: that mutant survived until this test was added).
    #[tokio::test]
    async fn accepts_exactly_64_bytes_of_report_data() {
        let exactly_max = vec![0u8; 64];
        match fetch_raw_quote(&exactly_max).await {
            Err(DstackAttestationError::RequestFailed(_)) => {}
            other => panic!("expected 64 bytes to pass validation and fail only on the socket call, got {other:?}"),
        }
    }

    // The flip side of nitro.rs's `fails_cleanly_without_the_nsm_device`:
    // off real TDX hardware (WSL2, CI, a bare instance) there is no dstack
    // guest agent socket, so this must fail cleanly with RequestFailed,
    // never panic. Not `#[ignore]`d -- costs nothing and runs everywhere.
    #[tokio::test]
    async fn fails_cleanly_without_the_dstack_socket() {
        match fetch_raw_quote(b"tachpawl-test").await {
            Err(DstackAttestationError::RequestFailed(_)) => {}
            other => panic!("expected RequestFailed off real TDX hardware, got {other:?}"),
        }
    }

    // The `verify_and_parse` analog of `nitro::verify_and_parse_rejects_
    // garbage_bytes_without_panicking` -- garbage input must fail cleanly
    // (either while locally parsing the claimed quote to find its FMSPC, or
    // once collateral fetch/verification itself rejects it), never panic.
    // Needs real network access (the collateral-fetch step) to run to
    // completion either way, so this is real-network-dependent, not fully
    // offline -- acceptable here since it costs only one HTTP round trip
    // and every CI/dev environment this project already runs in has
    // outbound internet access.
    #[tokio::test]
    async fn verify_and_parse_rejects_garbage_bytes_without_panicking() {
        let err = verify_and_parse(b"not a valid TDX quote").await.unwrap_err();
        assert!(
            matches!(err, DstackAttestationError::CollateralFetchFailed(_) | DstackAttestationError::VerificationFailed(_)),
            "expected a clean collateral-fetch or verification error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_and_parse_rejects_empty_bytes_without_panicking() {
        let err = verify_and_parse(&[]).await.unwrap_err();
        assert!(
            matches!(err, DstackAttestationError::CollateralFetchFailed(_) | DstackAttestationError::VerificationFailed(_)),
            "expected a clean collateral-fetch or verification error, got {err:?}"
        );
    }

    // The first genuine POSITIVE test this module has ever had, mirroring
    // nitro.rs's `real_fixture_from_a_genuinely_running_enclave_verifies_
    // successfully` -- every test above is negative (garbage/empty input, no
    // socket present). Captured 2026-10-01 from a real, throwaway Phala
    // Cloud TDX CVM (`crates/tee-adapter/examples/dstack_quote_probe.rs`,
    // run as `ghcr.io/crow-004/tachpawl-dstack-probe` inside that CVM, the
    // raw quote hex copied out of its own log output and decoded locally),
    // independently re-verified at capture time by that same probe run and
    // again here by the real `attestation-verifier` CLI binary (`RESULT: all
    // checks passed` against this exact fixture and MRTD). See TODO.md item
    // #15 for the full real-hardware account, including the three real
    // infra problems hit and fixed along the way (a private GHCR package, a
    // CVM stuck in "stopped" status, and the required-but-not-auto-injected
    // `/var/run/dstack.sock` volume mount).
    //
    // Deliberately NOT `#[ignore]`d, unlike the Nitro fixture test: a DCAP
    // quote's freshness is gated by `tcb_status` (checked against Intel's
    // live PCCS collateral on every call, including this one), not by an
    // X.509 leaf certificate's fixed few-hour validity window the way a
    // Nitro COSE_Sign1 document is -- so nothing about this fixture is
    // expected to start failing merely because time has passed, the same
    // reasoning that already lets `verify_and_parse_rejects_garbage_bytes_
    // without_panicking` above run unconditionally despite needing the same
    // real PCCS network round trip. If Intel ever revokes this specific
    // platform's TCB after capture, this test would start failing for a
    // real (if unlikely) reason, not a false one.
    #[tokio::test]
    async fn real_fixture_from_a_genuinely_running_tdx_cvm_verifies_successfully() {
        const REAL_MR_TD_HEX: &str = "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077";
        let quote = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test-fixtures/real-tdx-quote-2026-10-01.bin"))
            .expect("real fixture file should exist -- see TODO.md item #15");

        let facts = verify_and_parse(&quote).await.expect(
            "a real, previously-verified TDX quote should verify again -- if this fails, it is \
             either a real regression or (far less likely than Nitro's cert-expiry case) a real \
             TCB revocation for this platform after capture; any failure here is worth investigating",
        );

        assert!(!facts.is_debug, "this fixture was captured from a non-debug Phala Cloud TD (no debug-mode toggle exists there to test the opposite)");
        assert_eq!(facts.td_id, None, "a v4 quote from stock dstack/QEMU carries no per-launch td_id");
        let actual_mr_td = facts.mr_td.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(actual_mr_td, REAL_MR_TD_HEX, "MRTD must match the real CVM measurement recorded alongside this fixture");
    }

    /// A quote v5 shaped like Intel's `sgx_quote5_t`: 48-byte header (version
    /// first), body type, body size, then a body of `body_len` bytes with
    /// `td_id` written at offset 649 when the body is long enough. Signature
    /// bytes after the body are irrelevant to the layout and left out.
    fn synthetic_v5_quote(body_type: u16, body_len: usize, declared_len: u32, td_id: [u8; 32]) -> Vec<u8> {
        let mut quote = vec![0u8; QUOTE_V5_BODY_OFFSET + body_len];
        quote[0..2].copy_from_slice(&5u16.to_le_bytes());
        quote[4..8].copy_from_slice(&0x81u32.to_le_bytes()); // tee_type: TDX
        quote[48..50].copy_from_slice(&body_type.to_le_bytes());
        quote[50..54].copy_from_slice(&declared_len.to_le_bytes());
        if body_len >= TD15_EX_TD_ID_END {
            let start = QUOTE_V5_BODY_OFFSET + TD15_EX_TD_ID_OFFSET;
            quote[start..start + 32].copy_from_slice(&td_id);
        }
        quote
    }

    // Full size of Intel's `sgx_report2_body_v1_5_ex_t`: its last field,
    // `curr_server_td_attr`, is 8 bytes at offset 877.
    const TD15_EX_BODY_LEN: usize = 885;

    fn sample_td_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = 0xA0 ^ i as u8;
        }
        id
    }

    #[test]
    fn td_id_is_read_from_a_v5_quote_with_a_td15_ex_body() {
        let quote = synthetic_v5_quote(4, TD15_EX_BODY_LEN, TD15_EX_BODY_LEN as u32, sample_td_id());
        assert_eq!(td_id_from_quote(&quote), Ok(Some(sample_td_id())));
    }

    #[test]
    fn td_id_is_taken_from_offset_649_not_from_the_neighbouring_vmid_or_devinfo() {
        let mut quote = synthetic_v5_quote(4, TD15_EX_BODY_LEN, TD15_EX_BODY_LEN as u32, sample_td_id());
        quote[QUOTE_V5_BODY_OFFSET + 648] = 0x03; // vmid
        for b in &mut quote[QUOTE_V5_BODY_OFFSET + TD15_EX_TD_ID_END..QUOTE_V5_BODY_OFFSET + TD15_EX_TD_ID_END + 48] {
            *b = 0xFF; // devinfo
        }
        assert_eq!(td_id_from_quote(&quote), Ok(Some(sample_td_id())));
    }

    #[test]
    fn an_all_zero_td_id_means_the_host_did_not_enable_it() {
        let quote = synthetic_v5_quote(4, TD15_EX_BODY_LEN, TD15_EX_BODY_LEN as u32, [0u8; 32]);
        assert_eq!(td_id_from_quote(&quote), Ok(None));
    }

    #[test]
    fn v5_quotes_with_td10_or_td15_bodies_have_no_td_id() {
        for body_type in [2u16, 3] {
            let quote = synthetic_v5_quote(body_type, TD15_EX_BODY_LEN, TD15_EX_BODY_LEN as u32, sample_td_id());
            assert_eq!(td_id_from_quote(&quote), Ok(None), "body type {body_type}");
        }
    }

    #[test]
    fn a_v4_quote_has_no_td_id_even_if_offset_48_looks_like_body_type_4() {
        let mut quote = synthetic_v5_quote(4, TD15_EX_BODY_LEN, TD15_EX_BODY_LEN as u32, sample_td_id());
        quote[0..2].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(td_id_from_quote(&quote), Ok(None));
    }

    #[test]
    fn a_body_shorter_than_its_declared_size_is_rejected() {
        let quote = synthetic_v5_quote(4, 700, TD15_EX_BODY_LEN as u32, sample_td_id());
        assert_eq!(
            td_id_from_quote(&quote),
            Err(QuoteLayoutError::TruncatedBody { declared: TD15_EX_BODY_LEN, available: 700 })
        );
    }

    #[test]
    fn a_declared_body_ending_before_td_id_is_rejected() {
        let quote = synthetic_v5_quote(4, TD15_EX_BODY_LEN, 680, sample_td_id());
        assert_eq!(td_id_from_quote(&quote), Err(QuoteLayoutError::BodyTooShortForTdId(680)));
    }

    #[test]
    fn a_declared_body_ending_exactly_at_the_end_of_td_id_is_accepted() {
        let quote = synthetic_v5_quote(4, TD15_EX_TD_ID_END, TD15_EX_TD_ID_END as u32, sample_td_id());
        assert_eq!(td_id_from_quote(&quote), Ok(Some(sample_td_id())));
    }

    #[test]
    fn input_too_short_for_the_body_type_field_is_rejected_without_panicking() {
        assert_eq!(td_id_from_quote(&[]), Err(QuoteLayoutError::TooShortForHeader(0)));
        assert_eq!(td_id_from_quote(&[5, 0, 0]), Err(QuoteLayoutError::TooShortForHeader(3)));
        assert_eq!(td_id_from_quote(&[0u8; 53]), Err(QuoteLayoutError::TooShortForHeader(53)));
    }

    #[test]
    fn the_real_phala_v4_quote_has_no_td_id() {
        let quote = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test-fixtures/real-tdx-quote-2026-10-01.bin"))
            .expect("real fixture file should exist -- see TODO.md item #15");
        assert_eq!(u16::from_le_bytes([quote[0], quote[1]]), 4, "the fixture is a v4 quote");
        assert_eq!(td_id_from_quote(&quote), Ok(None));
    }

    #[test]
    fn td_attributes_indicate_debug_mode_detects_bit_0_set() {
        assert!(td_attributes_indicate_debug_mode([1, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn td_attributes_indicate_debug_mode_rejects_all_zero() {
        assert!(!td_attributes_indicate_debug_mode([0; 8]));
    }

    #[test]
    fn td_attributes_indicate_debug_mode_ignores_other_bits() {
        // Only bit 0 is DEBUG -- other attribute bits being set (real TDs
        // have several, e.g. SEPT_VE_DISABLE) must not be mistaken for it.
        assert!(!td_attributes_indicate_debug_mode([0b1111_1110, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn td_attributes_indicate_debug_mode_reads_little_endian() {
        // Bit 0 of the little-endian u64 is the FIRST byte's low bit, not
        // the last byte's -- a big-endian-by-mistake implementation would
        // fail this.
        assert!(!td_attributes_indicate_debug_mode([0, 0, 0, 0, 0, 0, 0, 1]));
        assert!(td_attributes_indicate_debug_mode([1, 0, 0, 0, 0, 0, 0, 0]));
    }
}
