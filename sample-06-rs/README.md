# sample-06-rs

Rust implementation of [`sample-06`](../sample-06/), which is fully compatible with the original version.

## Build

```shell:
$ cargo build --release
```

Then you have an executable binary `./target/release/cli06`.

## Usage

```shell:
$ ./target/release/cli06 -h
Rust version of sample-06

Usage: cli06 <COMMAND>

Commands:
  gen-hash        Generate Hash
  gen-hex-key     Generate hex key for HMAC generation
  gen-hmac        Generate HMAC (key length must be equal to that of hash.)
  verify-hmac     Verify HMAC
  gen-rsa-key     Generate RSA key pair
  sign-rsa-pss    Sign with RSASSA PSS
  verify-rsa-pss  Verify with RSASSA PSS
  gen-ecc-key     Generate ECC key pair
  sign-ecdsa      Sign with ECDSA
  verify-ecdsa    Verify with ECDSA
  help            Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```shell:
$ ../target/debug/cli06 gen-hash -h
Generate Hash

Usage: cli06 gen-hash [OPTIONS] <DATA>

Arguments:
  <DATA>  Data string to be hashed

Options:
  -a, --algorithm <ALGORITHM>  Name of hash function like 'SHA-256' [default: SHA-256]
  -h, --help                   Print help
```

```shell:
$ ../target/debug/cli06 gen-hex-key -h
Generate hex key for HMAC generation

Usage: cli06 gen-hex-key <LEN>

Arguments:
  <LEN>  key size in bytes

Options:
  -h, --help  Print help
```

```shell:
$ ../target/debug/cli06 gen-hmac -h
Generate HMAC (key length must be equal to that of hash.)

Usage: cli06 gen-hmac [OPTIONS] --key <KEY> <DATA>

Arguments:
  <DATA>  Data string to be keyed-hashed

Options:
  -k, --key <KEY>              Hex key of length equal to the hash size
  -a, --algorithm <ALGORITHM>  Name of hash function like 'SHA-256' [default: SHA-256]
  -h, --help                   Print help
```

```shell:
$ ../target/debug/cli06 verify-hmac -h
Verify HMAC

Usage: cli06 verify-hmac [OPTIONS] --key <KEY> --mac <MAC> <DATA>

Arguments:
  <DATA>  Data string to be keyed-hashed

Options:
  -k, --key <KEY>              Hex key of length equal to the hash size
  -m, --mac <MAC>              Hex HMAC
  -a, --algorithm <ALGORITHM>  Name of hash function like 'SHA-256' [default: SHA-256]
  -h, --help                   Print help
```

```shell:
$ ../target/debug/cli06 gen-rsa-key -h
Generate RSA key pair

Usage: cli06 gen-rsa-key [OPTIONS]

Options:
  -b, --bits <BITS>  Modulus length like 2048 [default: 2048]
  -h, --help         Print help
```

```shell:
$ ../target/debug/cli06 sign-rsa-pss -h
Sign with RSASSA PSS

Usage: cli06 sign-rsa-pss --privateKey <PRIVATE_KEY> <DATA>

Arguments:
  <DATA>  message data to be signed

Options:
  -s, --privateKey <PRIVATE_KEY>  hex DER-formatted private key
  -h, --help                      Print help
```

```shell:
$ ../target/debug/cli06 verify-rsa-pss -h
Verify with RSASSA PSS

Usage: cli06 verify-rsa-pss --publicKey <PUBLIC_KEY> --signature <SIGNATURE> <DATA>

Arguments:
  <DATA>  message data

Options:
  -p, --publicKey <PUBLIC_KEY>  hex DER-formatted public key
  -t, --signature <SIGNATURE>   hex signature
  -h, --help                    Print help
```

```shell:
$ ../target/debug/cli06 gen-ecc-key -h
Generate ECC key pair

Usage: cli06 gen-ecc-key [CURVE]

Arguments:
  [CURVE]  Curve name like P-256 [default: P-256]

Options:
  -h, --help  Print help
```

```shell:
$ ../target/debug/cli06 sign-ecdsa -h
Sign with ECDSA

Usage: cli06 sign-ecdsa --privateKey <PRIVATE_KEY> <DATA>

Arguments:
  <DATA>  message data to be signed

Options:
  -s, --privateKey <PRIVATE_KEY>  hex DER-formatted private key
  -h, --help                      Print help
```

```shell:
$ ../target/debug/cli06 verify-ecdsa -h
Verify with ECDSA

Usage: cli06 verify-ecdsa --publicKey <PUBLIC_KEY> --signature <SIGNATURE> <DATA>

Arguments:
  <DATA>  message data

Options:
  -p, --publicKey <PUBLIC_KEY>  hex DER-formatted public key
  -t, --signature <SIGNATURE>   hex signature
  -h, --help                    Print help
```
