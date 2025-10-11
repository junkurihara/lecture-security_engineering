use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ClapArgs {
  #[clap(subcommand)]
  pub subcommand: SubCommands,
}

#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug, Subcommand)]
pub enum SubCommands {
  /// Generate Hash
  Gen_Hash {
    /// Name of hash function like 'SHA-256'
    #[arg(short, long, default_value = "SHA-256")]
    algorithm: String,

    /// Data string to be hashed
    data: String,
  },
  /// Generate hex key for HMAC generation
  Gen_Hex_Key {
    /// key size in bytes
    len: usize,
  },
  /// Generate HMAC (key length must be equal to that of hash.)
  Gen_Hmac {
    /// Hex key of length equal to the hash size
    #[arg(short, long)]
    key: String,

    /// Name of hash function like 'SHA-256'
    #[arg(short, long, default_value = "SHA-256")]
    algorithm: String,

    /// Data string to be keyed-hashed
    data: String,
  },
  /// Verify HMAC
  Verify_Hmac {
    /// Hex key of length equal to the hash size
    #[arg(short, long)]
    key: String,

    /// Hex HMAC
    #[arg(short, long)]
    mac: String,

    /// Name of hash function like 'SHA-256'
    #[arg(short, long, default_value = "SHA-256")]
    algorithm: String,

    /// Data string to be keyed-hashed
    data: String,
  },
  /// Generate RSA key pair
  Gen_Rsa_key {
    ///  Modulus length like 2048
    #[arg(short, long, default_value = "2048")]
    bits: usize,
  },
  /// Sign with RSASSA PSS
  Sign_Rsa_Pss {
    /// hex DER-formatted private key
    #[arg(short = 's', long = "privateKey")]
    private_key: String,

    /// message data to be signed
    data: String,
  },
  /// Verify with RSASSA PSS
  Verify_Rsa_Pss {
    /// hex DER-formatted public key
    #[arg(short, long = "publicKey")]
    public_key: String,

    /// hex signature
    #[arg(short = 't', long)]
    signature: String,

    /// message data
    data: String,
  },
  /// Generate ECC key pair
  Gen_Ecc_key {
    /// Curve name like P-256
    #[arg(default_value = "P-256")]
    curve: String,
  },
  /// Sign with ECDSA
  Sign_Ecdsa {
    /// hex DER-formatted private key
    #[arg(short = 's', long = "privateKey")]
    private_key: String,

    /// message data to be signed
    data: String,
  },
  /// Verify with ECDSA
  Verify_Ecdsa {
    /// hex DER-formatted public key
    #[arg(short, long = "publicKey")]
    public_key: String,

    /// hex signature
    #[arg(short = 't', long)]
    signature: String,

    /// message data
    data: String,
  },
}
