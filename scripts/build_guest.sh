#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to an artifact directory outside the repository}"
python3 scripts/check_engine_features.py guest/Cargo.toml
# Same target/linker flags as the pinned upstream zkm-build. Build only: no
# execution, SDK initialization, credential discovery or local prover.
CARGO_ENCODED_RUSTFLAGS=$'-C\x1ftarget-cpu=mips32r2\x1f-C\x1ftarget-feature=+crt-static\x1f-C\x1flink-arg=-nostdlib\x1f-C\x1flink-arg=-g\x1f-C\x1flink-arg=--entry=main' \
  cargo +"${ZKM_GUEST_TOOLCHAIN:-zkm}" build --locked --release \
  --manifest-path guest/Cargo.toml --target mipsel-zkm-zkvm-elf
