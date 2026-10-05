//! The actual attestation-verification engine, extracted so it can be
//! genuinely open source: independently compilable by anyone, without also
//! needing access to the rest of Tachpawl's (proprietary) codebase.
//!
//! `tee-adapter` re-exports these same modules (`tee_adapter::attestation::
//! nitro`/`::dstack`) for its own internal use -- this crate is the single
//! source of truth for the verification logic; `tee-adapter` never
//! duplicates it. Moved here verbatim from `tee-adapter/src/attestation/
//! {nitro,dstack}.rs` (2026-09-29, see TODO.md item #11's "open, reproducible
//! verifier" plan) specifically because neither module ever depended on
//! `kdf-core` or anything else proprietary -- both `AttestationFacts` structs
//! are plain bytes/strings, so the split cost nothing architecturally.
//!
//! See the crate root `README.md` for what this is for and how to use the
//! `attestation-verifier` binary built on top of it.

#[cfg(feature = "nitro")]
pub mod nitro;

#[cfg(feature = "dstack")]
pub mod dstack;
