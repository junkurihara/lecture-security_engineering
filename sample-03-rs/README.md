# sample-03-rs

Rust implementation of [`sample-03`](../sample-03/), which is fully compatible with the original version.

## Build

```shell:
$ cargo build --release
```

Then you have an executable binary `./target/release/cli`.

## Usage

```shell:
$ ./target/release/cli03 -h
Rust version of sample-03

Usage: cli03 <COMMAND>

Commands:
  get   Get ciphertext or plaintext object from the json server
  post  Post ciphertext or plaintext object to the json server
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```shell:
$ ./target/release/post -h
Post ciphertext or plaintext object to the json server

Usage: cli03 post [OPTIONS] <DATA>

Arguments:
  <DATA>  Plaintext data string

Options:
  -k, --key <KEY>  Key string
  -e, --encrypt    Encrypt given data by AES-CBC
  -r, --remote     Post to the preset remote server (e2e.secarchlab.net) otherwise localhost:3000
  -h, --help       Print help
```

```shell:
$ ./target/release/get -h
Get ciphertext or plaintext object from the json server

Usage: cli03 get [OPTIONS] <ID>

Arguments:
  <ID>  Id number of the target data on the server

Options:
  -k, --key <KEY>  Key string
  -d, --decrypt    Decrypt given data by AES-CBC
  -r, --remote     Get from the preset remote server (e2e.secarchlab.net) otherwise localhost:3000
  -h, --help       Print help
```
