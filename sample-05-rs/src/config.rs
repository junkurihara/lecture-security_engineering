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
  /// Execute RSAES-OAEP encryption and decryption demo with RSA key generation
  Rsa_Oaep_Demo {
    /// plaintext data string
    data: String,
  },
  /// Generate RSA Key
  Rsa_Keygen {
    ///  Modulus length like 2048
    #[arg(default_value = "2048")]
    bits: usize,
  },
  /// RSA-OAEP Encryption
  Rsa_Oaep_Encrypt {
    /// hex DER-formatted public key
    #[arg(short, long = "publicKey")]
    public_key: String,

    /// plaintext data string
    data: String,
  },
  /// RSA-OAEP Decryption
  Rsa_Oaep_Decrypt {
    /// hex DER-formatted private key
    #[arg(short = 's', long = "privateKey")]
    private_key: String,

    /// encrypted data string
    data: String,
  },
  /// Generate ECC key pair and check the consistency of ECDH derived bits
  Check_Ecdh,
  /// Generate ECC Key
  Ecc_Keygen {
    /// Curve name like P-256
    #[arg(default_value = "P-256")]
    curve: String,
  },
  /// ECDH with AES Encryption
  Ecdh_Aes_Encrypt {
    /// hex DER-formatted public key
    #[arg(short, long = "publicKey")]
    public_key: String,

    /// hex DER-formatted private key
    #[arg(short = 's', long = "privateKey")]
    private_key: String,

    /// plaintext data string
    data: String,
  },
  /// ECDH with AES Decryption
  Ecdh_Aes_Decrypt {
    /// hex DER-formatted public key
    #[arg(short, long = "publicKey")]
    public_key: String,

    /// hex DER-formatted private key
    #[arg(short = 's', long = "privateKey")]
    private_key: String,

    /// encrypted and msgpacked data string in hex
    data: String,
  },
}
