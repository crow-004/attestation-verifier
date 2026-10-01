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
# Check a Nitro Enclave, live, run ON that machine (needs /dev/nsm), with a
# real random nonce for freshness proof -- prefer this form over the bare
# one below whenever you can run live. The round trip is verified
# automatically (a "nonce_roundtrip" check in the output) -- no need to
# pass the generated value back in yourself:
attestation-verifier --backend nitro --expect-pcr0 <published-pcr0-hex> --random-nonce

# Check a dstack/TDX node, live, run inside that VM. rt-mr3 is the field
# that actually distinguishes YOUR application/compose deployment from any
# other dstack app on the same base image -- mr-td alone does not (see
# "Known limitations" below); check it too whenever you have a published
# value for it:
attestation-verifier --backend dstack \
  --expect-mr-td <published-mr-td-hex> \
  --expect-rt-mr3 <published-rt-mr3-hex>

# Verify a quote/document obtained by some other means, from anywhere,
# without needing to be on that hardware at all:
attestation-verifier --backend nitro --expect-pcr0 <hex> --quote-file document.bin
```

Exit code `0` only if every check passes — every `--expect-*` you asked
for, plus (dstack only) the TCB-status check described below. At least one
`--expect-*` check is required — a run with none would trivially "pass" by
verifying nothing, exactly the false-confidence failure mode this tool
exists to prevent.

**TCB status (dstack only) is checked automatically, not opt-in.** A TDX
quote can be cryptographically valid while still reporting a platform that's
out of date or needs configuration changes — `dcap_qvl` itself only hard-
rejects `Revoked`. By default this tool additionally requires `UpToDate`;
pass `--allow-tcb-status <STATUS>` (repeatable) to accept others explicitly
(e.g. `--allow-tcb-status UpToDate --allow-tcb-status SWHardeningNeeded`).
There is no flag to skip this check entirely.

**Freshness, explained.** Without a nonce, a live check only proves "some
document this hardware once produced matches" — not "produced just now."
`--random-nonce` (generates, uses, prints, recommended) or `--live-nonce
<hex>` (you choose the value — dstack requires exactly 64 bytes, to avoid
this tool guessing how a shorter value gets padded) binds a fresh value into
the live fetch; the round trip is then verified automatically (a
`nonce_roundtrip`/`report_data_roundtrip` check appears in the output, no
extra flag needed). Both flags are live-fetch only (meaningless against
`--quote-file`, refused at parse time if combined). Separately,
`--expect-nonce <hex>`/`--expect-report-data <hex>` still exist for
checking a value you agreed on with whoever produced a RELAYED quote you're
verifying via `--quote-file` — a different use case from the automatic
live round trip.

**Choosing a PCCS (dstack only).** Collateral defaults to Phala's own
caching PCCS. `dcap_qvl::verify` independently checks that collateral's
signature chain up to Intel's real root CA regardless of which PCCS served
it, so this is a choice of availability/privacy, never of trust — override
with `--pccs-url <url>` if you'd rather ask Intel's own PCS or a self-hosted
mirror.

**Debug-mode enclaves/TDs are rejected by default, on both backends, not
opt-in.** A debug enclave's/TD's memory is readable by the host it runs on
-- a quote from one still cryptographically verifies (AWS signs Nitro debug
documents too; a debug TD's quote passes DCAP the same as any other), but
proves nothing about confidentiality. Detected precisely, not heuristically:
Nitro debug documents have PCR0 made up entirely of zero bytes (AWS's own
documented behavior); TDX debug TDs have bit 0 of `TD_ATTRIBUTES` set (cross-
checked against `Lanetus/TTKServer#17`'s own real implementation, not the
spec alone). Pass `--allow-debug` to accept one anyway -- for testing against
your own debug-mode instance, never for a node you're trusting for real.

## Checking someone else's node

Live mode (`--random-nonce`, no `--quote-file`) only works ON the node being
checked -- fine for self-checks, but the actual point of this tool is a
third party checking a node they don't operate. There's no automatic
"request a fresh quote from a remote node" transport here (that depends on
whatever channel the node operator exposes -- an API, SSH, a support
ticket), but once you have one, the recipe is the same on both backends:

1. Generate a nonce yourself: `openssl rand -hex 32` (nitro, any length) or
   `openssl rand -hex 64` (dstack, must be exactly 64 raw bytes / 128 hex
   chars).
2. Send that hex value to the node operator and ask them to run this, on
   the node, and send back the resulting file:
   ```bash
   attestation-verifier --backend nitro  --live-nonce <hex-you-sent> --dump-raw document.bin
   attestation-verifier --backend dstack --live-nonce <hex-you-sent> --dump-raw quote.bin
   ```
   `--dump-raw` saves the raw fetched bytes to a file and needs no
   `--expect-*` of its own (the operator doesn't need to know or trust any
   published measurement to do this step -- they're just a courier). The
   node still doesn't need any NEW code or endpoint for this to work: it's
   this same published CLI, already independently buildable, run once by
   whoever has access.
3. Once you have that file, verify it yourself, independently, checking the
   nonce came back unchanged (the actual freshness proof -- this is what
   stops a stale, previously-captured quote from passing as current):
   ```bash
   attestation-verifier --backend nitro  --quote-file document.bin --expect-pcr0 <hex> --expect-nonce <hex-you-sent>
   attestation-verifier --backend dstack --quote-file quote.bin    --expect-mr-td <hex> --expect-report-data <hex-you-sent>
   ```

This closes the same gap a fixed/no nonce would leave open: TDX quotes carry
no signed timestamp of their own (unlike Nitro's document, which does), so a
nonce you generated and verify came back unchanged is the only honest way to
know a quote was produced after you asked for it, not replayed from earlier.
The operator running step 2 still has to be someone you extend a minimum of
trust to for the handoff itself (they could refuse to run it, or claim a
different result than they got) -- this recipe proves the QUOTE is fresh and
genuine once you have it, not that the person who fetched it acted in good
faith getting it to you.

## Known limitations, disclosed plainly

Found by two rounds of real, independent code review (2026-09-30, 2026-10-01)
— one comparing this crate line-by-line against a much larger existing
attestation tool, the other against a real API-response-attestation project
with a genuinely different protocol but comparable trust reasoning — credit
due both times, and the reason most of what's documented above (TCB
enforcement, RTMR/PCR8 checks, nonce support, PCCS choice, debug-mode
rejection, `--dump-raw`, this whole section) exists at all. What's still
genuinely open:

- **Nitro's PCR8 support only compares a value you already trust.** PCR8 is
  the SHA-384 hash of the EIF's signing certificate, when present — this
  tool can check a live document's PCR8 against one you supply, but can't
  independently establish that certificate belongs to Velocity. Useful as
  an additional binding once you already trust a published PCR8, not a
  replacement for PCR0.
- **Certificate expiry IS checked, confirmed by reading the actual
  dependency source, not assumed — and a real self-correction along the way,
  worth stating plainly rather than quietly fixing.** A fair question the
  second review round raised (the crate's own docs.rs page doesn't make this
  obvious): does `attestation-doc-validation` reject a Nitro document signed
  by an expired certificate? Yes — `cert.rs`'s `validate_cert_trust_chain`
  gets the current time (`get_epoch()`, real `SystemTime::now()`) and passes
  it to `webpki::Time` / `verify_is_valid_tls_server_cert`, which checks
  NotBefore/NotAfter as a standard part of chain validation. An earlier draft
  of this note also claimed that crate exposes a `FAKETIME` env-var override
  "for that crate's own tests, worth remembering for this crate's own future
  fixture-based testing" — checked against the real raw source (not a
  summarizing tool's paraphrase, which is what produced the wrong claim in
  the first place) and that's only half right: `get_epoch()`'s `FAKETIME`
  branch is `#[cfg(test)]`-gated in `attestation-doc-validation` itself, so
  it compiles into THEIR test binary only, never into the published library
  this crate (or anything else) depends on normally. There is no way to
  override this check's clock from outside that crate's own test suite —
  confirmed empirically too: a real captured document still reported
  `all checks passed` even with `FAKETIME=2090844874` set, exactly as the
  `#[cfg(test)]` gating predicts. Nitro's leaf certificate is still
  documented to live only hours, so in practice this already gives offline
  mode a rough, real freshness bound on the Nitro side — a months-old saved
  document won't just fail on content, it'll fail on an
  expired leaf cert first. Not independently re-verified by THIS crate
  (would be redundant — it's already happening one layer down), and TDX's
  DCAP collateral freshness is a separate mechanism (`dcap_qvl::verify`
  against current TCB info), already documented above.
- **`--quote-file`/offline mode still has no built-in check for a STILL-VALID
  but stale quote/document** (distinct from an outright-expired one, which
  the point above now closes for Nitro, and from a revoked/rotated platform,
  which TCB-status rechecking already catches for dstack). See "Checking
  someone else's node" above for the actual honest fix — a nonce you
  generated and verify came back unchanged — now with `--dump-raw` making
  that a real, followable recipe instead of a theoretical one.
- **Live mode checks the hardware it's running on** — genuinely independent
  verification needs either a truly separate machine running this tool
  against a relayed `--quote-file`, or someone else entirely running the
  live check themselves. Running it live and trusting your own result isn't
  wrong, just not the "independent" half of what this tool is for.
- **No real saved fixture exists yet for a genuine positive test** ("a real
  attestation document/quote verifies successfully") — every existing test
  is negative (garbage input, no hardware present). Capturing one needs
  real Nitro/TDX hardware and is tracked, not silently skipped: see TODO.md
  item #15 in the main repository.
- **Nodes don't yet expose a "quote for this nonce" endpoint of their own**
  — the "Checking someone else's node" recipe above works today because
  this CLI itself can be run by the node operator, but a real design
  partner would reasonably want this built into `tee-service`/`hsm-service`
  directly rather than asking an operator to separately clone and run this
  tool. Tracked, not started: TODO.md item #15.

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
specification of how the published binary/hash below was produced. What's
actually pinned, following the same "name every input, don't just say
'reproducible'" discipline a real external review pointed to as worth
copying from another project's own reproducible-build writeup:

| Input | Pinned to | Why it matters if it weren't |
|---|---|---|
| Base image | `rust@sha256:7cc1c22d77...` (digest, not `rust:1-alpine`) | A floating tag resolves to whatever Rust/Alpine patch is current that day |
| Rust toolchain | `rust-toolchain.toml` → `1.98.1`, matching the base image's own rustc | A different compiler version can emit different code for identical source |
| Dependency versions | `Cargo.lock`, copied into the image, built with `--locked` | Without this (a real gap, closed 2026-10-01 — see the Dockerfile's own comment), patch releases of `dcap-qvl`/`dstack-sdk`/etc. silently drift the binary over time |
| File timestamps in debug info | `strip = true` (removes debug info entirely, the biggest realistic source) | Embedded build-time timestamps would make every build's bytes differ even from identical source |
| Codegen ordering | `codegen-units = 1` | Parallel codegen units can be scheduled/merged in a different order between runs |
| Absolute build path | `RUSTFLAGS=--remap-path-prefix=/build=/attestation-verifier-src` | `WORKDIR` is already fixed at `/build` regardless of the host's own checkout path, so this guards the cargo registry's own source-unpacking path instead, defensively |
| Build timestamp | `SOURCE_DATE_EPOCH=1700000000` | Defensive, not a fix for a confirmed problem — nothing in this specific build currently embeds it, but a future dependency addition might |

**Worth stating plainly, the same way that other project's writeup does**:
this only pins WHAT gets built, not that every crates.io dependency in the
tree is itself byte-for-byte reproducible from ITS OWN source — that's each
of those crates' own reproducibility story, outside this recipe's control.
And changing anything at all in this crate's own source — including a
comment with no behavioral effect — changes the resulting hash; that's the
correct, expected behavior of a hash, not a flaw to route around.

Reproduce it yourself:

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
55c6120f91551f00a2ffb7453c8b8b4283f84d4f0c552becf54263e3c519d524
```

Verified for real, not asserted: built twice, independently, with `--no-cache`
both times so Docker's own layer cache couldn't fake a match — both builds
produced this exact byte-identical binary. Reproduce that check yourself with
`scripts/wsl-check-attestation-verifier-reproducible-build.sh` in the main
repository, or with the two commands above run twice back to back.

(Updated 2026-10-01, twice the same day. First for the TCB/RTMR/PCCS/nonce
fixes — previous hash `df05ec1672be348e58c0daeafe3c190f6f1fb04b62e432c522ab18f321819b14`
(source as of 2026-09-29). Second, same day, for debug-mode rejection,
`--dump-raw`, and the `Cargo.lock`/`--locked` reproducible-build fix below —
previous hash `f13a22c56382c1ab80922a0830b424912ef90bf55bcc8939059243d39061a3d1`.
This crate's whole point is that the published hash always matches the
current source, so it's updated here every time the source changes, not
just at release milestones — both superseded hashes kept visible above
rather than quietly overwritten, same reason the main project's TODO.md
keeps superseded claims next to their corrections.)

## What this actually proves — scoped precisely, not oversold

This tool verifies one thing, generically, for *any* measurement you give
it: that a live TEE's hardware-signed attestation matches a hash you
supply. That check is real and the same regardless of what produced the
hash. What that check actually *means* depends entirely on whether the
code behind that hash is itself something you can independently read —
and here honesty requires separating two very different cases:

**For this crate's own code** (`nitro.rs`/`dstack.rs`/the CLI — everything
in this repo): the full chain closes. Read the source, build it
(reproducibly — you get the identical hash we publish), and if you ever
deployed this exact tool inside a TEE, `attestation-verifier` run by anyone
else could confirm the live instance is running the code you just read.
No gap, no leap of faith, for this code specifically.

**For Velocity's actual production nodes — `tee-service`, `hsm-service`**:
that chain does *not* close today, and we say so plainly rather than let
the framing above imply otherwise. Those binaries are what's actually
measured and checked in a real deployment, and their source is not public
— it's Velocity's proprietary core. So today, pointing `attestation-
verifier` at a real `tee-service`/`hsm-service` node proves the live
measurement matches whatever hash Velocity published — real value on its
own, since it catches silent tampering or drift between two checks over
time — but it does **not** let an outside party read the code behind that
hash and confirm it's honest, the way they could for this crate itself.
Closing that gap for the production binaries specifically needs one of:
an independent security audit of that source (under NDA, with the audit
firm publicly vouching for the exact commit and its hash — see the main
project's `TODO.md` item #15), or Velocity open-sourcing more of that
stack over time. Neither is done yet. Stated here precisely so nobody
reads more into "Code is Law" than what's actually true today.

## An open invitation

Regardless of that scope, the code that *is* here is fully open for
exactly the reason above: read it, try to break it, and open an issue (or
a pull request) on this repository with whatever you find — a security
issue, a logic error, or anything else worth fixing, in the verification
logic, the CLI, the Dockerfile, or the build recipe. That's not a courtesy
ask; it's the actual mechanism this project is built around. A verifier
nobody has ever tried to break is worth less than one that's genuinely
been looked at.
