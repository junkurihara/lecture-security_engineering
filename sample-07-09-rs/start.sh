#!/bin/bash

echo "Build fido2 client lib from TypeScript codes"
cd ../sample-07-09
pnpm cleanup && pnpm i && pnpm build && cp dist/*.bundle.js ../sample-07-09-rs/assets/

echo "Build fild2 server from Rust codes"
cd ../sample-07-09-rs
cargo build --release
../target/release/webauthn_sample
