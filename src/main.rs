//! Standalone, independently-compilable attestation verifier.
//!
//! The point: nobody should have to take Tachpawl's word for which measurement
//! a given TEE-backed node (a `NetworkedThresholdSigner` party, `authority-service`,
//! `tee-service`) is actually running. Anyone -- another MPC party, a design
//! partner, an auditor -- can `cargo build` this crate themselves from this
//! published source, and independently check any node against a published
//! expected measurement, without trusting Tachpawl's own verification claims.
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
//!   Pair with `--random-nonce` (or `--live-nonce <hex>`) plus a matching
//!   `--expect-nonce`/`--expect-report-data` to get a real, hardware-signed
//!   freshness proof -- without a nonce, a live check only proves "some
//!   document this hardware once produced matches," not "produced just now."
//! - **Offline** (`--quote-file <path>`): verifies raw bytes obtained by some
//!   other means (e.g. relayed from a remote node over a channel this tool
//!   doesn't need to know about), without needing to be on that hardware at
//!   all. `--live-nonce`/`--random-nonce` don't apply here (there's no live
//!   request to bind) -- but `--expect-nonce`/`--expect-report-data` still
//!   works, to check the file's embedded value against one agreed out of
//!   band with whoever produced it.
//!
//! ## Known limitations, disclosed plainly (not fixed in this pass)
//! - **Nitro PCR8 and nonce support exist as of 2026-09-30**, closing most of
//!   a real external review's findings (see TODO.md item #15) -- but this
//!   tool still can't independently establish that a Nitro EIF's signing
//!   certificate (the thing PCR8 measures) belongs to Tachpawl specifically;
//!   it can only compare PCR8 against a value you already trust came from
//!   Tachpawl through some other channel.
//! - **`--quote-file`/offline mode has no built-in quote-age limit.** DCAP
//!   collateral freshness (TCB info currency) is checked against wall-clock
//!   "now" inside `dcap_qvl::verify` itself, but the QUOTE's own age is not
//!   separately bounded -- a still-cert-valid but months-old quote from a
//!   node that has since been redeployed would still pass unless you also
//!   pass `--expect-report-data`/`--expect-nonce` with a value you know is
//!   recent. This is a real gap for fully unattended offline verification;
//!   the mitigating factor is that Revoked/rotated platforms ARE caught via
//!   the live TCB-status recheck DCAP performs against current collateral.

use std::fs;
use std::process::ExitCode;

fn print_usage() {
    eprintln!("attestation-verifier -- independently verify a Tachpawl TEE node's attestation");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  attestation-verifier --backend nitro  --expect-pcr0 <hex> [--expect-pcr8 <hex>] [--quote-file <path>]");
    eprintln!("  attestation-verifier --backend dstack --expect-mr-td <hex> [--expect-mr-config-id <hex>]");
    eprintln!("                       [--expect-rt-mr0 <hex>] [--expect-rt-mr1 <hex>] [--expect-rt-mr2 <hex>] [--expect-rt-mr3 <hex>]");
    eprintln!("                       [--allow-tcb-status <STATUS> ...] [--pccs-url <url>] [--quote-file <path>]");
    eprintln!();
    eprintln!("Without --quote-file: fetches a fresh quote/document live from THIS machine's");
    eprintln!("own attestation device (/dev/nsm for nitro, dstack's guest-agent socket for");
    eprintln!("dstack) -- only meaningful when run ON the node being checked.");
    eprintln!();
    eprintln!("With --quote-file <path>: verifies raw bytes read from that file instead --");
    eprintln!("usable from anywhere, e.g. checking a quote relayed from a remote node.");
    eprintln!();
    eprintln!("Checking a node you're ON (live mode, the two flags below):");
    eprintln!("  --random-nonce            generate, use, print, and auto-verify a real random nonce");
    eprintln!("  --live-nonce <hex>        use this exact nonce/report_data (dstack: must be 64 bytes)");
    eprintln!("  mutually exclusive with each other and with --quote-file; the round trip is");
    eprintln!("  checked automatically either way -- no extra flag needed.");
    eprintln!();
    eprintln!("Checking a node you're NOT on (offline mode, --quote-file + one round trip you");
    eprintln!("arrange yourself -- see README.md's \"Checking someone else's node\" for the full");
    eprintln!("recipe): send the node a nonce, have it embed that nonce in a quote by whatever");
    eprintln!("channel it exposes, save that quote to a file, then:");
    eprintln!("  --quote-file <path> --expect-nonce <hex>            (nitro)");
    eprintln!("  --quote-file <path> --expect-report-data <hex>      (dstack)");
    eprintln!();
    eprintln!("dstack-only:");
    eprintln!("  --allow-tcb-status <STATUS>   repeatable; default if omitted: UpToDate only.");
    eprintln!("                                the live TCB status is ALWAYS checked against this");
    eprintln!("                                allow-list -- there is no way to skip this check.");
    eprintln!("  --pccs-url <url>              use a PCCS other than Phala's default");
    eprintln!();
    eprintln!("Both backends, always checked, refuses a debug-mode enclave/TD by default (its");
    eprintln!("memory is host-readable -- a quote from one proves nothing about confidentiality");
    eprintln!("even though it still cryptographically verifies):");
    eprintln!("  --allow-debug             accept a debug-mode enclave/TD anyway (testing only)");
    eprintln!();
    eprintln!("Checking a node you don't operate (live mode only): --dump-raw <path> saves the");
    eprintln!("raw fetched document/quote to a file instead of only verifying it locally --");
    eprintln!("hand that file to whoever should independently verify it. Pair with --live-nonce");
    eprintln!("<hex> (a value THEY chose) so they can confirm it came back unchanged via");
    eprintln!("--expect-nonce/--expect-report-data once you send it over. Waives the \"at least");
    eprintln!("one --expect-*\" requirement below (a pure dump has nothing local to check).");
    eprintln!();
    eprintln!("Exit code 0 only if every check (TCB status, debug mode, and every --expect-*) passes;");
    eprintln!("at least one --expect-* check is required, unless --dump-raw is given.");
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    backend: String,
    quote_file: Option<String>,
    expect: Vec<(String, String)>,
    allow_tcb_status: Vec<String>,
    pccs_url: Option<String>,
    live_nonce_hex: Option<String>,
    random_nonce: bool,
    allow_debug: bool,
    dump_raw: Option<String>,
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut backend = None;
    let mut quote_file = None;
    let mut expect = Vec::new();
    let mut allow_tcb_status = Vec::new();
    let mut pccs_url = None;
    let mut live_nonce_hex = None;
    let mut random_nonce = false;
    let mut allow_debug = false;
    let mut dump_raw = None;
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
            "--allow-tcb-status" => {
                allow_tcb_status.push(next_value(raw, &mut i, flag)?);
                continue;
            }
            "--pccs-url" => {
                pccs_url = Some(next_value(raw, &mut i, flag)?);
                continue;
            }
            "--live-nonce" => {
                live_nonce_hex = Some(next_value(raw, &mut i, flag)?);
                continue;
            }
            "--random-nonce" => {
                random_nonce = true;
                i += 1;
                continue;
            }
            "--allow-debug" => {
                allow_debug = true;
                i += 1;
                continue;
            }
            "--dump-raw" => {
                dump_raw = Some(next_value(raw, &mut i, flag)?);
                continue;
            }
            "--expect-pcr0" => "pcr0",
            "--expect-pcr8" => "pcr8",
            "--expect-nonce" => "nonce",
            "--expect-mr-td" => "mr_td",
            "--expect-mr-config-id" => "mr_config_id",
            "--expect-rt-mr0" => "rt_mr0",
            "--expect-rt-mr1" => "rt_mr1",
            "--expect-rt-mr2" => "rt_mr2",
            "--expect-rt-mr3" => "rt_mr3",
            "--expect-report-data" => "report_data",
            other => return Err(format!("unrecognized argument: {other}")),
        };
        expect.push((field.to_string(), next_value(raw, &mut i, flag)?));
    }

    let backend = backend.ok_or_else(|| "--backend is required (nitro or dstack)".to_string())?;
    if backend != "nitro" && backend != "dstack" {
        return Err(format!("--backend must be \"nitro\" or \"dstack\", got \"{backend}\""));
    }
    if expect.is_empty() && dump_raw.is_none() {
        return Err("at least one --expect-* check is required (unless --dump-raw is given)".to_string());
    }
    if live_nonce_hex.is_some() && random_nonce {
        return Err("--live-nonce and --random-nonce are mutually exclusive".to_string());
    }
    if quote_file.is_some() && (live_nonce_hex.is_some() || random_nonce) {
        return Err("--live-nonce/--random-nonce only apply to a live fetch, not --quote-file".to_string());
    }
    if quote_file.is_some() && dump_raw.is_some() {
        return Err("--dump-raw only applies to a live fetch, not --quote-file (the file is already raw bytes)".to_string());
    }
    if allow_tcb_status.is_empty() {
        allow_tcb_status.push("UpToDate".to_string());
    }
    Ok(Args { backend, quote_file, expect, allow_tcb_status, pccs_url, live_nonce_hex, random_nonce, allow_debug, dump_raw })
}

fn next_value(raw: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let value = raw.get(*i + 1).ok_or_else(|| format!("{flag} needs a value"))?.clone();
    *i += 2;
    Ok(value)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The inverse of `hex_encode`, tolerating the same "0x"/case/whitespace
/// variations `hex_matches` already does -- used for `--live-nonce`, the one
/// place this tool needs to turn a caller-supplied hex string BACK into
/// bytes rather than just comparing two hex strings.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("invalid hex byte {:?}: {e}", &s[i..i + 2])))
        .collect()
}

/// A real random nonce -- via `getrandom` (OS CSPRNG), not a hand-rolled
/// time/pid-based value that an attacker could predict or precompute a
/// matching replay for. 32 bytes: comfortably under dstack's 64-byte
/// REPORTDATA cap and well within any Nitro NSM nonce limit seen in
/// practice. `len` is chosen by the caller per backend -- see `main`'s own
/// reasoning for why dstack specifically always gets exactly 64 bytes.
fn random_nonce_bytes(len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|e| format!("failed to get OS randomness for --random-nonce: {e}"))?;
    Ok(buf)
}

/// How many bytes `--random-nonce` should generate for a given backend.
/// dstack's REPORTDATA is a fixed 64-byte hardware field with an unconfirmed
/// padding behavior for shorter inputs (see `main`'s own doc comment on this
/// exact question) -- generating exactly 64 bytes sidesteps the ambiguity
/// entirely. Nitro's nonce has no such constraint; 32 bytes is simply ample.
fn random_nonce_len_for_backend(backend: &str) -> usize {
    if backend == "dstack" {
        64
    } else {
        32
    }
}

/// Pure validation for `--live-nonce` (a caller-supplied, not generated,
/// value): for dstack specifically, rejects anything other than exactly 64
/// bytes, for the same padding-ambiguity reason `random_nonce_len_for_backend`
/// exists. A no-op for any other backend.
fn validate_live_nonce_len(backend: &str, nonce: Vec<u8>) -> Result<Vec<u8>, String> {
    if backend == "dstack" && nonce.len() != 64 {
        return Err(format!(
            "--live-nonce must be exactly 64 bytes (128 hex chars) for --backend dstack -- got {} bytes",
            nonce.len()
        ));
    }
    Ok(nonce)
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

fn run_nitro(
    quote_file: Option<&str>,
    expect: &[(String, String)],
    live_nonce: Option<Vec<u8>>,
    allow_debug: bool,
    dump_raw: Option<&str>,
) -> Result<Vec<CheckResult>, String> {
    let document = match quote_file {
        Some(path) => fs::read(path).map_err(|e| format!("failed to read --quote-file {path}: {e}"))?,
        None => match &live_nonce {
            Some(nonce) => attestation_verifier::nitro::fetch_raw_document_with_nonce(nonce)
                .map_err(|e| format!("fetch_raw_document_with_nonce failed: {e} (expected unless run on real Nitro hardware)"))?,
            None => attestation_verifier::nitro::fetch_raw_document()
                .map_err(|e| format!("fetch_raw_document failed: {e} (expected unless run on real Nitro hardware)"))?,
        },
    };

    // Saved before verification, deliberately -- the point is handing this
    // file to whoever should independently verify it, which must not
    // depend on THIS run's own (possibly incomplete or absent) --expect-*
    // checks succeeding.
    if let Some(path) = dump_raw {
        fs::write(path, &document).map_err(|e| format!("failed to write --dump-raw {path}: {e}"))?;
        println!("raw attestation document saved to {path} ({} bytes)", document.len());
    }

    let facts = attestation_verifier::nitro::verify_and_parse(&document).map_err(|e| format!("verify_and_parse failed: {e}"))?;
    println!("VERIFIED real Nitro attestation document. module_id: {}", facts.module_id);

    // Not opt-in, same reasoning as dstack's tcb_status check below: a
    // debug-mode enclave's document still cryptographically verifies (AWS
    // signs these too) but proves nothing about confidentiality (the host
    // can read a debug enclave's memory). Detected as an all-zero PCR0, per
    // AWS's own documented behavior -- see `nitro::AttestationFacts::
    // is_debug`'s doc comment for the exact quote.
    let mut results = vec![CheckResult {
        field: "debug_mode".to_string(),
        expected: if allow_debug { "debug allowed".to_string() } else { "not debug".to_string() },
        actual: if facts.is_debug { "debug".to_string() } else { "not debug".to_string() },
        passed: !facts.is_debug || allow_debug,
    }];

    // When a live nonce was sent, the round-trip check is automatic -- not
    // something the caller has to separately ask for via --expect-nonce,
    // which would be impossible to do in one command line for
    // --random-nonce anyway (the value doesn't exist until this function
    // generates it). This is the actual freshness proof: the hardware
    // signed a nonce chosen just before this call, into a document produced
    // just now, not replayed from earlier.
    if let Some(sent) = &live_nonce {
        println!("live nonce sent for this fetch: {}", hex_encode(sent));
        let received = facts.nonce.as_deref().map(hex_encode);
        results.push(CheckResult {
            field: "nonce_roundtrip".to_string(),
            expected: hex_encode(sent),
            actual: received.unwrap_or_else(|| "<none returned>".to_string()),
            passed: facts.nonce.as_deref() == Some(sent.as_slice()),
        });
    }

    results.extend(evaluate(expect, |field| match field {
        "pcr0" => Ok(hex_encode(&facts.pcr0)),
        "pcr8" => facts.pcr8.as_deref().map(hex_encode).ok_or_else(|| {
            "this document has no PCR8 entry (EIF was not built with a signing certificate)".to_string()
        }),
        "nonce" => facts.nonce.as_deref().map(hex_encode).ok_or_else(|| {
            "this document has no nonce (fetched without --live-nonce/--random-nonce, or read from --quote-file)".to_string()
        }),
        other => Err(format!("--expect-{other} is not a valid check for --backend nitro (pcr0, pcr8, nonce)")),
    })?);

    Ok(results)
}

#[allow(clippy::too_many_arguments)]
async fn run_dstack(
    quote_file: Option<&str>,
    expect: &[(String, String)],
    allow_tcb_status: &[String],
    pccs_url: Option<&str>,
    live_nonce: Option<Vec<u8>>,
    allow_debug: bool,
    dump_raw: Option<&str>,
) -> Result<Vec<CheckResult>, String> {
    let quote = match quote_file {
        Some(path) => fs::read(path).map_err(|e| format!("failed to read --quote-file {path}: {e}"))?,
        None => {
            let report_data = live_nonce.clone().unwrap_or_else(|| b"tachpawl-attestation-verifier-v1".to_vec());
            attestation_verifier::dstack::fetch_raw_quote(&report_data)
                .await
                .map_err(|e| format!("fetch_raw_quote failed: {e} (expected unless run inside a real dstack TDX VM)"))?
                .quote
        }
    };

    if let Some(path) = dump_raw {
        fs::write(path, &quote).map_err(|e| format!("failed to write --dump-raw {path}: {e}"))?;
        println!("raw TDX quote saved to {path} ({} bytes)", quote.len());
    }

    let facts = match pccs_url {
        Some(url) => attestation_verifier::dstack::verify_and_parse_with_pccs(&quote, url).await,
        None => attestation_verifier::dstack::verify_and_parse(&quote).await,
    }
    .map_err(|e| format!("verify_and_parse failed: {e}"))?;
    println!("VERIFIED real TDX DCAP quote. tcb_status: {}, advisory_ids: {:?}", facts.tcb_status, facts.advisory_ids);

    // The TCB-status check is not opt-in -- it runs on every dstack
    // invocation, live or offline, and is prepended to the caller's own
    // --expect-* results so `print_results`'s existing all-or-nothing
    // pass/fail logic covers it automatically. `Revoked` never reaches here
    // at all (dcap_qvl::verify itself hard-rejects it before this function
    // gets a result); this is the layer that additionally refuses
    // "technically not revoked, but not the fresh/patched state you asked
    // for" statuses like OutOfDate or ConfigurationNeeded, unless the
    // caller explicitly opted into accepting them via --allow-tcb-status.
    let tcb_ok = allow_tcb_status.iter().any(|allowed| allowed.eq_ignore_ascii_case(&facts.tcb_status));
    let mut results = vec![
        CheckResult {
            field: "tcb_status".to_string(),
            expected: allow_tcb_status.join(" or "),
            actual: facts.tcb_status.clone(),
            passed: tcb_ok,
        },
        // Same reasoning as run_nitro's identical check -- a debug TD's
        // memory is host-readable, so a quote from one proves nothing about
        // confidentiality even though it still cryptographically verifies.
        // Cross-checked against Lanetus/TTKServer#17's own real
        // implementation, not derived from the Intel spec alone -- see
        // `dstack::AttestationFacts::is_debug`'s doc comment.
        CheckResult {
            field: "debug_mode".to_string(),
            expected: if allow_debug { "debug allowed".to_string() } else { "not debug".to_string() },
            actual: if facts.is_debug { "debug".to_string() } else { "not debug".to_string() },
            passed: !facts.is_debug || allow_debug,
        },
    ];

    // Same automatic-round-trip reasoning as run_nitro's identical block --
    // see its comment. Only added when the caller explicitly opted into a
    // real nonce (--random-nonce/--live-nonce); the default fixed
    // report_data string used otherwise proves nothing about recency, so
    // auto-checking it back would be a no-op, not a real freshness proof.
    if let Some(sent) = &live_nonce {
        // `main` already enforced sent.len() == 64 for this backend, so
        // this is a direct comparison, no padding assumption involved.
        println!("live nonce (report_data) sent for this fetch: {}", hex_encode(sent));
        results.push(CheckResult {
            field: "report_data_roundtrip".to_string(),
            expected: hex_encode(sent),
            actual: hex_encode(&facts.report_data),
            passed: facts.report_data.as_slice() == sent.as_slice(),
        });
    }

    results.extend(evaluate(expect, |field| match field {
        "mr_td" => Ok(hex_encode(&facts.mr_td)),
        "mr_config_id" => Ok(hex_encode(&facts.mr_config_id)),
        "rt_mr0" => Ok(hex_encode(&facts.rt_mr0)),
        "rt_mr1" => Ok(hex_encode(&facts.rt_mr1)),
        "rt_mr2" => Ok(hex_encode(&facts.rt_mr2)),
        "rt_mr3" => Ok(hex_encode(&facts.rt_mr3)),
        "report_data" => Ok(hex_encode(&facts.report_data)),
        other => Err(format!(
            "--expect-{other} is not a valid check for --backend dstack (mr-td, mr-config-id, rt-mr0..3, report-data)"
        )),
    })?);

    Ok(results)
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

    // dstack's REPORTDATA is a fixed 64-byte hardware field; this crate
    // (and `dstack-sdk` itself, confirmed against its real published
    // source, not guessed) accepts a shorter caller-supplied value and
    // forwards it as-is, but how dstack's OWN guest agent pads a short
    // value up to 64 bytes for the real quote isn't confirmed anywhere in
    // that source -- left-pad, right-pad, and "reject" are all plausible
    // and this crate won't guess. Requiring exactly 64 bytes here removes
    // the ambiguity entirely rather than risk a round-trip check that's
    // wrong about its own padding assumption and spuriously fails on
    // correctly-working hardware. Nitro's nonce has no such ambiguity (its
    // ByteBuf round-trips whatever was sent, confirmed via docs.rs), so
    // only dstack gets this constraint.
    let nonce_len = random_nonce_len_for_backend(&args.backend);

    let live_nonce = if args.random_nonce {
        match random_nonce_bytes(nonce_len) {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else if let Some(hex) = &args.live_nonce_hex {
        match hex_decode(hex).and_then(|n| validate_live_nonce_len(&args.backend, n)) {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("error: invalid --live-nonce: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    let results = match args.backend.as_str() {
        "nitro" => run_nitro(args.quote_file.as_deref(), &args.expect, live_nonce, args.allow_debug, args.dump_raw.as_deref()),
        "dstack" => {
            run_dstack(
                args.quote_file.as_deref(),
                &args.expect,
                &args.allow_tcb_status,
                args.pccs_url.as_deref(),
                live_nonce,
                args.allow_debug,
                args.dump_raw.as_deref(),
            )
            .await
        }
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

    fn base_args(extra: &[&str]) -> Vec<String> {
        let mut raw = vec![s("--backend"), s("nitro"), s("--expect-pcr0"), s("aabb")];
        raw.extend(extra.iter().map(|x| x.to_string()));
        raw
    }

    #[test]
    fn parse_args_accepts_a_real_nitro_invocation() {
        let raw = vec![s("--backend"), s("nitro"), s("--expect-pcr0"), s("aabb")];
        let args = parse_args(&raw).expect("valid args must parse");
        assert_eq!(args.backend, "nitro");
        assert_eq!(args.quote_file, None);
        assert_eq!(args.expect, vec![(s("pcr0"), s("aabb"))]);
        // Fail-closed default, not an empty allow-list.
        assert_eq!(args.allow_tcb_status, vec![s("UpToDate")]);
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
    fn parse_args_accepts_rt_mr_and_report_data_expectations() {
        let raw = vec![
            s("--backend"),
            s("dstack"),
            s("--expect-rt-mr3"),
            s("33"),
            s("--expect-report-data"),
            s("44"),
        ];
        let args = parse_args(&raw).expect("valid args must parse");
        assert_eq!(args.expect, vec![(s("rt_mr3"), s("33")), (s("report_data"), s("44"))]);
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
    fn parse_args_defaults_allow_tcb_status_to_uptodate_only() {
        let args = parse_args(&base_args(&["--backend", "dstack", "--expect-mr-td", "aa"])).expect("valid");
        assert_eq!(args.allow_tcb_status, vec![s("UpToDate")]);
    }

    #[test]
    fn parse_args_accepts_multiple_allow_tcb_status_values() {
        let raw = vec![
            s("--backend"),
            s("dstack"),
            s("--expect-mr-td"),
            s("aa"),
            s("--allow-tcb-status"),
            s("UpToDate"),
            s("--allow-tcb-status"),
            s("SWHardeningNeeded"),
        ];
        let args = parse_args(&raw).expect("valid");
        assert_eq!(args.allow_tcb_status, vec![s("UpToDate"), s("SWHardeningNeeded")]);
    }

    #[test]
    fn parse_args_accepts_pccs_url() {
        let raw = vec![s("--backend"), s("dstack"), s("--expect-mr-td"), s("aa"), s("--pccs-url"), s("https://example.com/pccs")];
        let args = parse_args(&raw).expect("valid");
        assert_eq!(args.pccs_url, Some(s("https://example.com/pccs")));
    }

    #[test]
    fn parse_args_accepts_random_nonce() {
        let raw = vec![s("--backend"), s("nitro"), s("--expect-pcr0"), s("aa"), s("--random-nonce")];
        let args = parse_args(&raw).expect("valid");
        assert!(args.random_nonce);
        assert_eq!(args.live_nonce_hex, None);
    }

    #[test]
    fn parse_args_defaults_allow_debug_to_false() {
        let args = parse_args(&base_args(&[])).expect("valid");
        assert!(!args.allow_debug);
    }

    #[test]
    fn parse_args_accepts_allow_debug() {
        let raw = vec![s("--backend"), s("nitro"), s("--expect-pcr0"), s("aa"), s("--allow-debug")];
        let args = parse_args(&raw).expect("valid");
        assert!(args.allow_debug);
    }

    #[test]
    fn parse_args_accepts_dump_raw_with_no_expect_checks() {
        // The whole point of --dump-raw: an operator who doesn't know or
        // care about expected measurement values should still be able to
        // fetch-and-save without being forced to supply a placeholder
        // --expect-*.
        let raw = vec![s("--backend"), s("nitro"), s("--dump-raw"), s("/tmp/out.bin")];
        let args = parse_args(&raw).expect("valid");
        assert_eq!(args.dump_raw, Some(s("/tmp/out.bin")));
        assert!(args.expect.is_empty());
    }

    #[test]
    fn parse_args_rejects_dump_raw_with_quote_file() {
        let raw = vec![
            s("--backend"),
            s("nitro"),
            s("--quote-file"),
            s("/tmp/in.bin"),
            s("--expect-pcr0"),
            s("aa"),
            s("--dump-raw"),
            s("/tmp/out.bin"),
        ];
        let err = parse_args(&raw).unwrap_err();
        assert!(err.contains("--dump-raw"), "got: {err}");
    }

    #[test]
    fn parse_args_still_requires_expect_without_dump_raw() {
        let raw = vec![s("--backend"), s("nitro")];
        let err = parse_args(&raw).unwrap_err();
        assert!(err.contains("--expect"), "got: {err}");
    }

    #[test]
    fn parse_args_accepts_live_nonce_hex() {
        let raw = vec![s("--backend"), s("nitro"), s("--expect-pcr0"), s("aa"), s("--live-nonce"), s("deadbeef")];
        let args = parse_args(&raw).expect("valid");
        assert_eq!(args.live_nonce_hex, Some(s("deadbeef")));
        assert!(!args.random_nonce);
    }

    #[test]
    fn parse_args_rejects_live_nonce_and_random_nonce_together() {
        let raw = vec![
            s("--backend"),
            s("nitro"),
            s("--expect-pcr0"),
            s("aa"),
            s("--live-nonce"),
            s("deadbeef"),
            s("--random-nonce"),
        ];
        let err = parse_args(&raw).unwrap_err();
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn parse_args_rejects_random_nonce_with_quote_file() {
        let raw = vec![
            s("--backend"),
            s("nitro"),
            s("--expect-pcr0"),
            s("aa"),
            s("--quote-file"),
            s("/tmp/q.bin"),
            s("--random-nonce"),
        ];
        let err = parse_args(&raw).unwrap_err();
        assert!(err.contains("--quote-file"), "got: {err}");
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
    fn hex_decode_round_trips_with_hex_encode() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn hex_decode_tolerates_0x_prefix_and_case() {
        assert_eq!(hex_decode("0xAABBCC").unwrap(), vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(hex_decode("aabbcc").unwrap(), vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_rejects_non_hex_characters() {
        assert!(hex_decode("zz").is_err());
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
        let err = run_nitro(Some(path.to_str().unwrap()), &expect, None, false, None).unwrap_err();
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
        let err = run_nitro(None, &expect, None, false, None).unwrap_err();
        assert!(err.contains("fetch_raw_document failed"), "expected a clean no-hardware error, got: {err}");
    }

    #[test]
    fn run_nitro_with_live_nonce_fails_cleanly_when_live_fetch_has_no_real_hardware() {
        // Same as above, through the --live-nonce path specifically (a
        // different function, fetch_raw_document_with_nonce) -- must fail
        // the same clean way, not panic or silently skip the nonce.
        let expect = vec![(s("pcr0"), s("aabb"))];
        let err = run_nitro(None, &expect, Some(vec![1, 2, 3]), false, None).unwrap_err();
        assert!(
            err.contains("fetch_raw_document_with_nonce failed"),
            "expected a clean no-hardware error naming the nonce path, got: {err}"
        );
    }

    #[test]
    fn random_nonce_bytes_produces_the_requested_length_and_is_not_all_zero() {
        // Not a strong randomness test (that's getrandom's own job, already
        // audited elsewhere) -- just confirms this function actually calls
        // through rather than e.g. returning an all-zero buffer by mistake,
        // and honors the caller-chosen length (main() relies on this to
        // enforce dstack's exactly-64-bytes constraint).
        let n = random_nonce_bytes(32).expect("OS randomness should be available in any test environment");
        assert_eq!(n.len(), 32);
        assert!(n.iter().any(|&b| b != 0), "32 real random bytes being all-zero is astronomically unlikely");

        let n64 = random_nonce_bytes(64).expect("OS randomness should be available in any test environment");
        assert_eq!(n64.len(), 64);
    }

    #[test]
    fn random_nonce_bytes_are_not_identical_across_two_calls() {
        let a = random_nonce_bytes(32).unwrap();
        let b = random_nonce_bytes(32).unwrap();
        assert_ne!(a, b, "two independent random nonces colliding would indicate a broken RNG, not bad luck");
    }

    #[test]
    fn random_nonce_len_for_backend_is_64_only_for_dstack() {
        assert_eq!(random_nonce_len_for_backend("dstack"), 64);
        assert_eq!(random_nonce_len_for_backend("nitro"), 32);
    }

    #[test]
    fn validate_live_nonce_len_accepts_exactly_64_bytes_for_dstack() {
        let nonce = vec![0u8; 64];
        assert_eq!(validate_live_nonce_len("dstack", nonce.clone()).unwrap(), nonce);
    }

    #[test]
    fn validate_live_nonce_len_rejects_short_nonce_for_dstack() {
        let err = validate_live_nonce_len("dstack", vec![0u8; 32]).unwrap_err();
        assert!(err.contains("64 bytes"), "got: {err}");
    }

    #[test]
    fn validate_live_nonce_len_rejects_long_nonce_for_dstack() {
        let err = validate_live_nonce_len("dstack", vec![0u8; 65]).unwrap_err();
        assert!(err.contains("64 bytes"), "got: {err}");
    }

    #[test]
    fn validate_live_nonce_len_is_a_noop_for_nitro() {
        // Nitro's nonce has no fixed-length constraint -- any length the
        // caller supplies passes through unchanged.
        assert_eq!(validate_live_nonce_len("nitro", vec![1, 2, 3]).unwrap(), vec![1, 2, 3]);
    }
}
