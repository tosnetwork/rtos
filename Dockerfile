FROM rust:slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    make \
    clang \
    libssl-dev \
    libzstd-dev \
    libgoogle-perftools-dev

COPY . /rtos
WORKDIR /rtos

ARG GIT_BRANCH
ARG GIT_COMMIT
ARG GIT_COMMIT_DATE
ARG RUSTFLAGS=""

ENV GIT_BRANCH=${GIT_BRANCH}
ENV GIT_COMMIT=${GIT_COMMIT}
ENV GIT_COMMIT_DATE=${GIT_COMMIT_DATE}
ENV RUSTFLAGS=${RUSTFLAGS}

RUN cargo build --release --bin rtos --bin console --bin secrets-vault-cli

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3t64 \
    libzstd1 \
    libgoogle-perftools4t64 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /rtos/target/release/rtos /usr/local/bin/
COPY --from=builder /rtos/target/release/console /usr/local/bin/
COPY --from=builder /rtos/target/release/secrets-vault-cli /usr/local/bin/

WORKDIR /rtos
