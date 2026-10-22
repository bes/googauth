#!/bin/bash

set -e
set -x
export RUST_BACKTRACE=1

# Check workspace crates
cargo fmt --all -- --check
cargo check --workspace --all-features
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
