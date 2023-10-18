#!/bin/bash

echo "Build fido2 client lib from TypeScript codes"
cd ../sample-07-09
pnpm cleanup && pnpm i && pnpm build && cp dist/*.bundle.js ../sample-07-09-rs/assets/

echo "Build fido2 server from Rust codes"
cd ../sample-07-09-rs
cargo build --release

echo "Run fido2 server"
../target/release/webauthn_sample
