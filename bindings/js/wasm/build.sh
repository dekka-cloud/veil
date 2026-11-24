#!/bin/sh
# Builds the WebAssembly half of the npm package into bindings/js/wasm/pkg. Needs the
# wasm32-unknown-unknown target and a wasm-bindgen CLI of the same version as the
# wasm-bindgen crate in Cargo.lock; wasm-opt from binaryen shrinks the result when present.
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"
target_dir=${CARGO_TARGET_DIR:-$root/target}
cargo build -p veil-wasm --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir bindings/js/wasm/pkg --out-name veil_wasm \
  "$target_dir/wasm32-unknown-unknown/release/veil_wasm.wasm"
if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int \
    -o bindings/js/wasm/pkg/veil_wasm_bg.wasm bindings/js/wasm/pkg/veil_wasm_bg.wasm
fi
