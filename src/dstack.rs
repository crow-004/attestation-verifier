//! Real attestation via dstack's guest-agent socket (`/var/run/dstack.sock`)
//! -- the Intel TDX equivalent of Nitro's `/dev/nsm` device. Exists only
//! inside a real dstack-managed TDX confidential VM (e.g. a Phala Cloud
//! CVM); TODO.md item #11 has the real deployment this was verified
//! against (`velocity-tee-service` running on Phala Cloud).
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
    /// `kdf_core::VerificationEngine`'s job, not this module's.
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
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
    let collateral_client = dcap_qvl::collateral::CollateralClient::with_default_http(dcap_qvl::collateral::PHALA_PCCS_URL)
        .map_err(|e| DstackAttestationError::CollateralFetchFailed(e.to_string()))?;
    let collateral = collateral_client.fetch(quote).await.map_err(|e| DstackAttestationError::CollateralFetchFailed(e.to_string()))?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs();

    let verified =
        dcap_qvl::verify::verify(quote, &collateral, now_secs).map_err(|e| DstackAttestationError::VerificationFailed(e.to_string()))?;

    let td_report = verified.report.as_td10().ok_or(DstackAttestationError::NotATdxReport)?;

    Ok(AttestationFacts {
        mr_td: td_report.mr_td,
        rt_mr0: td_report.rt_mr0,
        rt_mr1: td_report.rt_mr1,
        rt_mr2: td_report.rt_mr2,
        rt_mr3: td_report.rt_mr3,
        mr_config_id: td_report.mr_config_id,
        mr_owner: td_report.mr_owner,
        mr_owner_config: td_report.mr_owner_config,
        report_data: td_report.report_data,
        tcb_status: verified.status,
        advisory_ids: verified.advisory_ids,
    })
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
        match fetch_raw_quote(b"velocity-test").await {
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
}
