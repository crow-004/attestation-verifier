# attestation-verifier

Independent, open-source (MIT OR Apache-2.0) verification of Velocity's
TEE-backed nodes — AWS Nitro Enclaves and Intel TDX (via dstack's guest
agent). Nobody has to take Velocity's word for which measurement a given
node is actually running: this crate is meant to be cloned and compiled by
anyone — another MPC party, a design partner's own security team, an
independent auditor — and pointed at a node they want to check themselves.

## Why this exists

Velocity's `HSM_AUTHORITY` role can run as a networked MPC threshold signer
(`NetworkedThresholdSigner`), where multiple independent parties each hold
one share of the signing key and no single party ever holds the whole key.
That property only holds if the parties are genuinely independent — if the
same operator ends up running every party's node, wrapping each one in a
TEE (so not even that operator can read a share directly) is worth doing.
But TEE attestation only proves *what code is running* — it doesn't prove
that code is honest, unless the code itself can be independently reviewed
and its measurement independently reproduced. This crate is the second half
of that story (the first half is the reproducible-build work — see the main
project's `TODO.md` item #15): given a published, audited commit and its
expected measurement, this tool lets anyone check that a live node is
actually running it.

## What this is not

This crate adds **no new cryptography**. Every actual verification step —
the COSE_Sign1 signature and certificate-chain check to AWS's real Nitro
root CA (`nitro.rs`, via the `attestation-doc-validation` crate), and the
DCAP certificate-chain check against Intel's real PCCS collateral
(`dstack.rs`, via `dcap-qvl`) — already existed, already unit-tested, in
Velocity's own `tee-adapter` crate before this split. `tee-adapter`
re-exports these same modules for its own internal use rather than
duplicating them; this crate is the single source of truth for both.

## Using it

```bash
# Check a Nitro Enclave, live, run ON that machine (needs /dev/nsm):
attestation-verifier --backend nitro --expect-pcr0 <published-pcr0-hex>

# Check a dstack/TDX node, live, run inside that VM:
attestation-verifier --backend dstack --expect-mr-td <published-mr-td-hex>

# Verify a quote/document obtained by some other means, from anywhere,
# without needing to be on that hardware at all:
attestation-verifier --backend nitro --expect-pcr0 <hex> --quote-file document.bin
```

Exit code `0` only if every `--expect-*` check passes. At least one check
is required — a run with none would trivially "pass" by verifying nothing,
exactly the false-confidence failure mode this tool exists to prevent.

## Building it yourself

```bash
cargo build --release -p attestation-verifier
```

No workspace-wide setup needed — this crate's own `Cargo.toml`/`Cargo.lock`
list every dependency and pinned version it needs, and its own
`rust-toolchain.toml` pins the compiler — builds independently of the rest
of this repository, and independently of whatever toolchain happens to be
installed on your machine.

## Reproducing the published build, exactly

This crate's `Dockerfile` is not just a convenience — it's the actual
specification of how the published binary/hash below was produced: a pinned
base image (by digest, not a floating tag), a pinned Rust toolchain, `strip
= true` + `codegen-units = 1` to remove the two biggest realistic sources of
non-determinism, and `--remap-path-prefix` so the build's own working
directory never leaks into the binary. Reproduce it yourself:

```bash
docker build --no-cache --target build -t attestation-verifier-check -f Dockerfile .
docker run --rm attestation-verifier-check \
  sha256sum /build/target/x86_64-unknown-linux-musl/release/attestation-verifier
```

If that hash doesn't match the one published below, something is genuinely
wrong — either with this README, or with the copy you're building from — and
that mismatch is exactly what this whole mechanism exists to let you catch
yourself, without needing to trust this document either.

## Our principle: Code is Law! and provable honesty

We don't ask you to trust our word that this tool does what it says, and we
don't ask you to trust that the binary we ship matches the source we publish
here. We built it so you never have to: the source is public, the build
recipe is public and pinned down to the exact compiler and base-image
digest, and the resulting hash is public too. Compile it yourself, compare
the hash yourself, and if it matches, you know — not because we said so, but
because you checked.

To be precise about what this actually is, and isn't: publishing our own
hash is not "we audited ourselves." Nobody should trust a self-audit for the
threat this tool exists to address in the first place — a party operating
its own TEE-wrapped node, with nobody else able to check what's really
running inside it. What this mechanism actually gives you is narrower and
more honest than a self-certification: that the hash we publish genuinely
corresponds to the source we publish, verifiable by anyone, not just us,
without needing our permission or our cooperation. That is what "Code is
Law" means here — not "trust our review," but "the rule is public, and
checkable by you, right now."

```
sha256 (attestation-verifier, x86_64-unknown-linux-musl, release):
df05ec1672be348e58c0daeafe3c190f6f1fb04b62e432c522ab18f321819b14
```

Verified for real, not asserted: built twice, independently, with `--no-cache`
both times so Docker's own layer cache couldn't fake a match — both builds
produced this exact byte-identical binary. Reproduce that check yourself with
`scripts/wsl-check-attestation-verifier-reproducible-build.sh` in the main
repository, or with the two commands above run twice back to back.

## What's verified vs. what you still have to trust

- **Verified by this tool, cryptographically**: the attestation document/
  quote is genuinely signed by real hardware (AWS's Nitro root CA, or
  Intel's DCAP root via a PCCS), and its measurement matches the value you
  supplied.
- **Not verified by this tool**: that the expected measurement you supplied
  actually corresponds to source code that does what it claims. That link
  comes from a reproducible build plus an independent audit of the exact
  commit that measurement was built from — outside this tool's scope, see
  the main project's `TODO.md` for that side of the story.
