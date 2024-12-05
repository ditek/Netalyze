#!/bin/bash
# Build netalyze for x86 and aarch64
# Usage: ./build.sh [x86|aarch64]

cd $(dirname $0)
ARCH=$1

if [ "$ARCH" == "x86" ]; then
    cargo build --release
    cp target/release/netalyze release/netalyze_x86
elif [ "$ARCH" == "aarch64" ]; then
    cross build --release
    cp target/aarch64-unknown-linux-gnu/release/netalyze release/netalyze_aarch64
else
    cargo build --release
    cross build --release
    cp target/release/netalyze release/netalyze_x86
    cp target/aarch64-unknown-linux-gnu/release/netalyze release/netalyze_aarch64
fi