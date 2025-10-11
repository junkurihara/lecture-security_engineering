#!/bin/bash

echo "Build fido2 client lib from TypeScript codes"
cd ./frontend-lib
pnpm cleanup && pnpm i && pnpm build && cp dist/*.bundle.js ../assets/

echo "Build fido2 server from Rust codes"
cd ..
cargo build --release

echo "Run fido2 server"
../target/release/webauthn_sample
