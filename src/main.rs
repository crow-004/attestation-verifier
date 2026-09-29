//! Standalone, independently-compilable attestation verifier.
//!
//! The point: nobody should have to take Velocity's word for which measurement
//! a given TEE-backed node (a `NetworkedThresholdSigner` party, `hsm-service`,
//! `tee-service`) is actually running. Anyone -- another MPC party, a design
//! partner, an auditor -- can `cargo build` this crate themselves from this
//! published source, and independently check any node against a published
//! expected measurement, without trusting Velocity's own verification claims.
//! See TODO.md item #11's "open, reproducible verifier" plan and item #15's
//! reproducible-build work, which this tool is the other half of: item #15
//! lets someone confirm a published measurement corresponds to an audited
//! commit; this tool lets them confirm a LIVE node's measurement matches that
//! published value.
//!
//! Deliberately thin, on purpose: all the actual cryptographic verification --
//! COSE_Sign1 + AWS root CA chain for Nitro, DCAP cert chain + Intel PCCS
//! collateral for TDX -- is this crate's own `attestation_verifier::
//! {nitro,dstack}::verify_and_parse` (in `lib.rs`, `tee-adapter` re-exports
//! the same modules for its own internal use, never duplicates them),
//! already unit-tested, already run against real hardware (see TODO.md
//! item #11).
//! This binary adds only: fetching or reading the input bytes, and comparing
//! the resulting facts against a caller-supplied expected value. No new
//! cryptography lives here.
//!
//! Two modes:
//! - **Live** (default): run ON the machine being checked -- inside the
//!   enclave, or with access to its attestation device -- and this fetches a
//!   fresh quote/document itself. Meaningless run anywhere else (fails
//!   cleanly, matching every other real-attestation path in this project).
//! - **Offline** (`--quote-file <path>`): verifies raw bytes obtained by some
//!   other means (e.g. relayed from a remote node over a channel this tool
//!   doesn't need to know about), without needing to be on that hardware at
//!   all.

use std::fs;
use std::process::ExitCode;

fn print_usage() {
    eprintln!("attestation-verifier -- independently verify a Velocity TEE node's attestation");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  attestation-verifier --backend nitro  --expect-pcr0 <hex> [--quote-file <path>]");
    eprintln!("  attestation-verifier --backend dstack --expect-mr-td <hex> [--expect-mr-config-id <hex>] [--quote-file <path>]");
    eprintln!();
    eprintln!("Without --quote-file: fetches a fresh quote/document live from THIS machine's");
    eprintln!("own attestation device (/dev/nsm for nitro, dstack's guest-agent socket for");
    eprintln!("dstack) -- only meaningful when run ON the node being checked.");
    eprintln!();
    eprintln!("With --quote-file <path>: verifies raw bytes read from that file instead --");
    eprintln!("usable from anywhere, e.g. checking a quote relayed from a remote node.");
    eprintln!();
    eprintln!("Exit code 0 only if every --expect-* check passes; at least one is required.");
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    backend: String,
    quote_file: Option<String>,
    expect: Vec<(String, String)>,
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut backend = None;
    let mut quote_file = None;
    let mut expect = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let flag = raw[i].as_str();
        let field = match flag {
            "--backend" => {
                backend = Some(next_value(raw, &mut i, flag)?);
                continue;
            }
            "--quote-file" => {
                quote_file = Some(next_value(raw, &mut i, flag)?);
                continue;
            }
            "--expect-pcr0" => "pcr0",
            "--expect-mr-td" => "mr_td",
            "--expect-mr-config-id" => "mr_config_id",
            other => return Err(format!("unrecognized argument: {other}")),
        };
        expect.push((field.to_string(), next_value(raw, &mut i, flag)?));
    }

    let backend = backend.ok_or_else(|| "--backend is required (nitro or dstack)".to_string())?;
    if backend != "nitro" && backend != "dstack" {
        return Err(format!("--backend must be \"nitro\" or \"dstack\", got \"{backend}\""));
    }
    if expect.is_empty() {
        return Err("at least one --expect-* check is required".to_string());
    }
    Ok(Args { backend, quote_file, expect })
}

fn next_value(raw: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let value = raw.get(*i + 1).ok_or_else(|| format!("{flag} needs a value"))?.clone();
    *i += 2;
    Ok(value)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Pure comparison, unit-testable without any hardware, network, or file
/// I/O: does the actual (already hex-encoded) value match the caller-
/// supplied expected one? Tolerates surrounding whitespace, a leading
/// "0x", and case, since a hex string pasted from a terminal or a published
/// doc is not always byte-for-byte identical in formatting.
fn hex_matches(expected: &str, actual_hex: &str) -> bool {
    fn normalize(s: &str) -> String {
        s.trim().trim_start_matches("0x").trim_start_matches("0X").to_ascii_lowercase()
    }
    normalize(expected) == normalize(actual_hex)
}

#[derive(Debug)]
struct CheckResult {
    field: String,
    expected: String,
    actual: String,
    passed: bool,
}

fn evaluate(expect: &[(String, String)], lookup: impl Fn(&str) -> Result<String, String>) -> Result<Vec<CheckResult>, String> {
    expect
        .iter()
        .map(|(field, expected)| {
            let actual = lookup(field)?;
            Ok(CheckResult { field: field.clone(), passed: hex_matches(expected, &actual), expected: expected.clone(), actual })
        })
        .collect()
}

fn print_results(results: &[CheckResult]) -> bool {
    let mut all_passed = true;
    for r in results {
        let status = if r.passed { "PASS" } else { "FAIL" };
        if !r.passed {
            all_passed = false;
        }
        println!("[{status}] {}: expected {} actual {}", r.field, r.expected, r.actual);
    }
    all_passed
}

fn run_nitro(quote_file: Option<&str>, expect: &[(String, String)]) -> Result<Vec<CheckResult>, String> {
    let document = match quote_file {
        Some(path) => fs::read(path).map_err(|e| format!("failed to read --quote-file {path}: {e}"))?,
        None => attestation_verifier::nitro::fetch_raw_document()
            .map_err(|e| format!("fetch_raw_document failed: {e} (expected unless run on real Nitro hardware)"))?,
    };
    let facts = attestation_verifier::nitro::verify_and_parse(&document).map_err(|e| format!("verify_and_parse failed: {e}"))?;
    println!("VERIFIED real Nitro attestation document. module_id: {}", facts.module_id);

    evaluate(expect, |field| match field {
        "pcr0" => Ok(hex_encode(&facts.pcr0)),
        other => Err(format!("--expect-{other} is not a valid check for --backend nitro (only pcr0)")),
    })
}

async fn run_dstack(quote_file: Option<&str>, expect: &[(String, String)]) -> Result<Vec<CheckResult>, String> {
    let quote = match quote_file {
        Some(path) => fs::read(path).map_err(|e| format!("failed to read --quote-file {path}: {e}"))?,
        None => {
            let report_data = b"velocity-attestation-verifier-v1".to_vec();
            attestation_verifier::dstack::fetch_raw_quote(&report_data)
                .await
                .map_err(|e| format!("fetch_raw_quote failed: {e} (expected unless run inside a real dstack TDX VM)"))?
                .quote
        }
    };
    let facts = attestation_verifier::dstack::verify_and_parse(&quote).await.map_err(|e| format!("verify_and_parse failed: {e}"))?;
    println!("VERIFIED real TDX DCAP quote. tcb_status: {}, advisory_ids: {:?}", facts.tcb_status, facts.advisory_ids);

    evaluate(expect, |field| match field {
        "mr_td" => Ok(hex_encode(&facts.mr_td)),
        "mr_config_id" => Ok(hex_encode(&facts.mr_config_id)),
        other => Err(format!("--expect-{other} is not a valid check for --backend dstack (only mr-td, mr-config-id)")),
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!();
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    let results = match args.backend.as_str() {
        "nitro" => run_nitro(args.quote_file.as_deref(), &args.expect),
        "dstack" => run_dstack(args.quote_file.as_deref(), &args.expect).await,
        _ => unreachable!("parse_args already validated backend"),
    };

    match results {
        Ok(results) => {
            if print_results(&results) {
                println!("RESULT: all checks passed");
                ExitCode::SUCCESS
            } else {
                println!("RESULT: at least one check failed");
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn parse_args_accepts_a_real_nitro_invocation() {
        let raw = vec![s("--backend"), s("nitro"), s("--expect-pcr0"), s("aabb")];
        let args = parse_args(&raw).expect("valid args must parse");
        assert_eq!(args.backend, "nitro");
        assert_eq!(args.quote_file, None);
        assert_eq!(args.expect, vec![(s("pcr0"), s("aabb"))]);
    }

    #[test]
    fn parse_args_accepts_quote_file_and_multiple_expectations() {
        let raw = vec![
            s("--backend"),
            s("dstack"),
            s("--quote-file"),
            s("/tmp/q.bin"),
            s("--expect-mr-td"),
            s("11"),
            s("--expect-mr-config-id"),
            s("22"),
        ];
        let args = parse_args(&raw).expect("valid args must parse");
        assert_eq!(args.quote_file, Some(s("/tmp/q.bin")));
        assert_eq!(args.expect, vec![(s("mr_td"), s("11")), (s("mr_config_id"), s("22"))]);
    }

    #[test]
    fn parse_args_rejects_missing_backend() {
        let raw = vec![s("--expect-pcr0"), s("aabb")];
        let err = parse_args(&raw).unwrap_err();
        assert!(err.contains("--backend"), "error must name the missing flag, got: {err}");
    }

    #[test]
    fn parse_args_rejects_an_unknown_backend_name() {
        let raw = vec![s("--backend"), s("sgx"), s("--expect-pcr0"), s("aabb")];
        let err = parse_args(&raw).unwrap_err();
        assert!(err.contains("nitro"), "error must explain valid backends, got: {err}");
    }

    #[test]
    fn parse_args_rejects_zero_expectations() {
        // A run with no --expect-* would trivially "pass" by checking
        // nothing -- exactly the false-confidence failure mode this whole
        // tool exists to prevent, so it's refused outright rather than
        // silently reporting success.
        let raw = vec![s("--backend"), s("nitro")];
        let err = parse_args(&raw).unwrap_err();
        assert!(err.contains("--expect"), "error must explain at least one check is required, got: {err}");
    }

    #[test]
    fn parse_args_rejects_a_flag_missing_its_value() {
        let raw = vec![s("--backend")];
        let err = parse_args(&raw).unwrap_err();
        assert!(err.contains("--backend"));
    }

    #[test]
    fn parse_args_rejects_an_unrecognized_flag() {
        let raw = vec![s("--backend"), s("nitro"), s("--expect-pcr9000"), s("aabb")];
        let err = parse_args(&raw).unwrap_err();
        assert!(err.contains("--expect-pcr9000"), "error must name the actual unrecognized flag, got: {err}");
    }

    #[test]
    fn hex_matches_is_case_and_whitespace_and_0x_prefix_insensitive() {
        assert!(hex_matches("AABBCC", "aabbcc"));
        assert!(hex_matches("  aabbcc  ", "aabbcc"));
        assert!(hex_matches("0xaabbcc", "aabbcc"));
        assert!(hex_matches("0XAABBCC", "aabbcc"));
    }

    #[test]
    fn hex_matches_rejects_a_real_mismatch() {
        // A mutant that made this always return true would defeat the
        // entire point of the tool -- silently reporting PASS regardless
        // of the actual measurement. Pinned explicitly.
        assert!(!hex_matches("aabbcc", "aabbcd"));
        assert!(!hex_matches("aabbcc", "aabbccdd"));
    }

    #[test]
    fn evaluate_reports_pass_and_fail_independently_per_field() {
        let expect = vec![(s("a"), s("11")), (s("b"), s("22"))];
        let results = evaluate(&expect, |field| match field {
            "a" => Ok(s("11")),  // matches
            "b" => Ok(s("ff")),  // does not match
            _ => unreachable!(),
        })
        .unwrap();
        assert!(results[0].passed);
        assert!(!results[1].passed);
    }

    #[test]
    fn evaluate_propagates_a_lookup_error_for_an_invalid_field_name() {
        let expect = vec![(s("not-a-real-field"), s("11"))];
        let err = evaluate(&expect, |field| Err(format!("unknown field {field}"))).unwrap_err();
        assert!(err.contains("not-a-real-field"));
    }

    #[test]
    fn print_results_returns_true_only_when_every_check_passed() {
        let all_pass = vec![CheckResult { field: s("a"), expected: s("1"), actual: s("1"), passed: true }];
        assert!(print_results(&all_pass));

        let one_fail = vec![
            CheckResult { field: s("a"), expected: s("1"), actual: s("1"), passed: true },
            CheckResult { field: s("b"), expected: s("2"), actual: s("3"), passed: false },
        ];
        assert!(!print_results(&one_fail));
    }

    #[test]
    fn run_nitro_fails_cleanly_on_a_garbage_quote_file() {
        // The real point of the offline mode's error path: garbage bytes
        // must be rejected by verify_and_parse's own COSE_Sign1/cert-chain
        // check, not panic, and not silently report success.
        let dir = std::env::temp_dir().join(format!("attestation-verifier-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("garbage.bin");
        std::fs::write(&path, b"this is not a real attestation document").unwrap();

        let expect = vec![(s("pcr0"), s("aabb"))];
        let err = run_nitro(Some(path.to_str().unwrap()), &expect).unwrap_err();
        assert!(err.contains("verify_and_parse failed"), "expected a clean verification error, got: {err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn run_nitro_fails_cleanly_when_live_fetch_has_no_real_hardware() {
        // This process (a plain `cargo test` run, not a real Nitro Enclave)
        // has no /dev/nsm -- confirms the live-fetch path degrades to a
        // clear error rather than hanging or panicking, same discipline as
        // every other real-attestation path in this project.
        let expect = vec![(s("pcr0"), s("aabb"))];
        let err = run_nitro(None, &expect).unwrap_err();
        assert!(err.contains("fetch_raw_document failed"), "expected a clean no-hardware error, got: {err}");
    }
}
