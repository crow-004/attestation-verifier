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
COPY Cargo.toml ./
COPY src ./src
# --remap-path-prefix: WORKDIR is already the fixed /build regardless of the
# host machine's own checkout path -- this guards against the cargo
# registry's own source-unpacking path leaking into debug info. Defensive,
# not a fix for a confirmed problem -- same reasoning as the other two
# Dockerfiles in this repo. SOURCE_DATE_EPOCH likewise defensive.
ENV SOURCE_DATE_EPOCH=1700000000
ENV RUSTFLAGS="--remap-path-prefix=/build=/attestation-verifier-src"
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=build /build/target/x86_64-unknown-linux-musl/release/attestation-verifier /attestation-verifier
ENTRYPOINT ["/attestation-verifier"]
