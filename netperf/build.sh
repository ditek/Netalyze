#!/bin/bash
cd $(dirname $0)
cargo build --release
cross build --release

cp target/release/netperf ../release/netperf_x86
cp target/aarch64-unknown-linux-gnu/release/netperf ../release/netperf_aarch64
