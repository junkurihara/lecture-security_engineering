# sample-05-rs

Rust implementation of [`sample-05`](../sample-05/), which is fully compatible with the original version.

## Build

```shell:
$ cargo build --release
```

Then you have an executable binary `./target/release/cli05`.

## Usage

```shell:
$ ./target/release/cli04 -h
Rust version of sample-05

Usage: cli05 <COMMAND>

Commands:
  rsa-oaep-demo     Execute RSAES-OAEP encryption and decryption demo with RSA key generation
  rsa-keygen        Generate RSA Key
  rsa-oaep-encrypt  RSA-OAEP Encryption
  rsa-oaep-decrypt  RSA-OAEP Decryption
  check-ecdh        Generate ECC key pair and check the consistency of ECDH derived bits
  ecc-keygen        Generate ECC Key
  ecdh-aes-encrypt  ECDH with AES Encryption
  ecdh-aes-decrypt  ECDH with AES Decryption
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```shell:
$ ../target/debug/cli05 rsa-oaep-demo -h
Execute RSAES-OAEP encryption and decryption demo with RSA key generation

Usage: cli05 rsa-oaep-demo <DATA>

Arguments:
  <DATA>  plaintext data string

Options:
  -h, --help  Print help
```

```shell:
$ ../target/debug/cli05 rsa-keygen -h
Generate RSA Key

Usage: cli05 rsa-keygen [BITS]

Arguments:
  [BITS]  Modulus length like 2048 [default: 2048]

Options:
  -h, --help  Print help
```

```shell:
$ ../target/debug/cli05 rsa-oaep-encrypt -h
RSA-OAEP Encryption

Usage: cli05 rsa-oaep-encrypt --publicKey <PUBLIC_KEY> <DATA>

Arguments:
  <DATA>  plaintext data string

Options:
  -p, --publicKey <PUBLIC_KEY>  hex DER-formatted public key
  -h, --help                    Print help
```

```shell:
$ ../target/debug/cli05 rsa-oaep-decrypt -h
RSA-OAEP Decryption

Usage: cli05 rsa-oaep-decrypt --privateKey <PRIVATE_KEY> <DATA>

Arguments:
  <DATA>  encrypted data string

Options:
  -s, --privateKey <PRIVATE_KEY>  hex DER-formatted private key
  -h, --help                      Print help
```

```shell:
$ ../target/debug/cli05 check-ecdh -h
Generate ECC key pair and check the consistency of ECDH derived bits

Usage: cli05 check-ecdh

Options:
  -h, --help  Print help
```

```shell:
$ ../target/debug/cli05 ecc-keygen -h
Generate ECC Key

Usage: cli05 ecc-keygen [CURVE]

Arguments:
  [CURVE]  Curve name like P-256 [default: P-256]

Options:
  -h, --help  Print help
```

```shell:
$ ../target/debug/cli05 ecdh-aes-encrypt -h
ECDH with AES Encryption

Usage: cli05 ecdh-aes-encrypt --publicKey <PUBLIC_KEY> --privateKey <PRIVATE_KEY> <DATA>

Arguments:
  <DATA>  plaintext data string

Options:
  -p, --publicKey <PUBLIC_KEY>    hex DER-formatted public key
  -s, --privateKey <PRIVATE_KEY>  hex DER-formatted private key
  -h, --help                      Print help
```

```shell:
$ ../target/debug/cli05 ecdh-aes-decrypt -h
ECDH with AES Decryption

Usage: cli05 ecdh-aes-decrypt --publicKey <PUBLIC_KEY> --privateKey <PRIVATE_KEY> <DATA>

Arguments:
  <DATA>  encrypted and msgpacked data string in hex

Options:
  -p, --publicKey <PUBLIC_KEY>    hex DER-formatted public key
  -s, --privateKey <PRIVATE_KEY>  hex DER-formatted private key
  -h, --help                      Print help
```
