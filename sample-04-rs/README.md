# sample-04-rs

Rust implementation of [`sample-04`](../sample-04/), which is fully compatible with the original version.

## Build

```shell:
$ cargo build --release
```

Then you have an executable binary `./target/release/cli04`.

## Usage

```shell:
$ ./target/release/cli04 -h
Rust version of sample-04

Usage: cli04 <COMMAND>

Commands:
  get         Get ciphertext or plaintext object from the json server
  post        Post ciphertext or plaintext object to the json server
  gen-secret  Generate master secret
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```shell:
$ ./target/release/cli04 post -h
Post ciphertext or plaintext object to the json server

Usage: cli04 post [OPTIONS] <DATA>

Arguments:
  <DATA>  Plaintext data string

Options:
  -p, --password <PASSWORD>  Password
  -m, --master <MASTER>      Master secret in base64
  -r, --remote               Post to the preset remote server (e2e.secarchlab.net) otherwise localhost:3000
  -h, --help                 Print help
```

```shell:
$ ./target/release/cli04 get -h
Get ciphertext or plaintext object from the json server

Usage: cli04 get [OPTIONS] <ID>

Arguments:
  <ID>  Id number of the target data on the server

Options:
  -p, --password <PASSWORD>  Password
  -m, --master <MASTER>      Master secret in base64
  -r, --remote               Get from the preset remote server (e2e.secarchlab.net) otherwise localhost:3000
  -h, --help                 Print help
```

```shell:
$ ./target/release/cli04 gen-secret -h
Generate master secret

Usage: cli04 gen-secret <LEN>

Arguments:
  <LEN>  Length of secret

Options:
  -h, --help  Print help
```
