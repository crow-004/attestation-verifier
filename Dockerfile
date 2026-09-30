# Reproducible-build recipe (TODO.md item #15), applied to this crate.
# Static-musl for the same reason as docker/Dockerfile.hsm-service and
# docker/Dockerfile.tee-service: portable to a minimal root filesystem (this
# binary is meant to be run FROM INSIDE the enclave being checked, in live
# mode, where there may be no shell or dynamic libc to speak of), and it
# doubles as the exact recipe anyone rebuilding this crate to verify the
# published hash should use -- this Dockerfile IS the specification, not just
# a convenience.
#
# Pinned by digest, not a floating tag: reproducible-build verification means
# a third party rebuilds this independently and expects byte-identical
# output. This digest is rust:1-alpine as resolved 2026-09-27 (rustc 1.98.1,
# Alpine 3.24.2) -- the same one already used for hsm-service/tee-service;
# matches this crate's own rust-toolchain.toml pin -- move both together.
FROM rust@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS build
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# --remap-path-prefix: WORKDIR is already the fixed /build regardless of the
# host machine's own checkout path -- this guards against the cargo
# registry's own source-unpacking path leaking into debug info. Defensive,
# not a fix for a confirmed problem -- same reasoning as the other two
# Dockerfiles in this repo. SOURCE_DATE_EPOCH likewise defensive.
ENV SOURCE_DATE_EPOCH=1700000000
ENV RUSTFLAGS="--remap-path-prefix=/build=/attestation-verifier-src"
# --locked: a real, previously-undisclosed gap, closed 2026-10-01 after a
# real external review compared this recipe against another project's own
# reproducible-build writeup. Before this, Cargo.lock was never copied into
# the image, so a build's dependency patch versions floated to whatever was
# current on crates.io that day -- two builds run close together (this
# crate's own reproducibility check) happened to agree, but a rebuild weeks
# later against a newer dcap-qvl/dstack-sdk patch release would silently
# diverge from the published hash, looking like tampering when it was just
# time passing. --locked makes cargo fail outright rather than silently
# re-resolve if Cargo.lock and Cargo.toml ever disagree.
RUN cargo build --release --locked --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=build /build/target/x86_64-unknown-linux-musl/release/attestation-verifier /attestation-verifier
ENTRYPOINT ["/attestation-verifier"]
