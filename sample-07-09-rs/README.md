# A sample server/client of FIDO2 WebAuthn/Passkeys

**NOTE: This example doesn't capable with untrusted CA-certified passkeys**. We recommend to use Yubico Security Key or YubiKey to play with this example.

## How to run

You need Rust/Cargo environment in addition to Node.js v20+ at first. You can serve a sample WebAuthn registration/authentication server listening on `127.0.0.1:8080` as follows. Note that `start.sh` builds our TypeScript library located in `../sample-07-09/` to call from the frontend along with the rust server.

```shell:
% cd sample-07-09-rs
% bash ./start.sh
```

## Usage of Rust-based server

```shell:
% ../target/release/webauthn_sample --help
Rust version of sample-07-09-rs

Usage: webauthn_sample [OPTIONS]

Options:
  -l, --listen-addr <LISTEN_ADDR>  Listen socket [default: 127.0.0.1:8080]
  -a, --asset-dir <ASSET_DIR>      Asset directory [default: ./assets]
  -h, --help                       Print help
  -V, --version                    Print version
```
