mod config;
mod ecc;
mod error;
mod hash;
mod rsa;
mod util;

use crate::{ecc::*, error::*, hash::*, rsa::*, util::*};
use clap::Parser;
use config::{ClapArgs, SubCommands};
use ecc::import_pkcs8_der;

pub fn main() -> Result<()> {
  let _ = include_str!("../Cargo.toml");
  let args = ClapArgs::parse();

  match &args.subcommand {
    SubCommands::Gen_Hash { algorithm, data } => {
      let data = data.as_bytes();
      let digest = match algorithm.as_str() {
        "SHA-256" => generate_hash::<sha2::Sha256>(data),
        "SHA-384" => generate_hash::<sha2::Sha384>(data),
        "SHA-512" => generate_hash::<sha2::Sha512>(data),
        "SHA3-256" => generate_hash::<sha3::Sha3_256>(data),
        "SHA3-384" => generate_hash::<sha3::Sha3_384>(data),
        "SHA3-512" => generate_hash::<sha3::Sha3_512>(data),
        _ => bail!("Unsupported hash algorithm: {}", algorithm),
      };
      println!("<Computed Hash>\n{}\n", digest.to_hex_string());
    }
    SubCommands::Gen_Hex_Key { len } => {
      use rand::RngCore;
      let mut buf = vec![0u8; *len];
      rand::rng().fill_bytes(&mut buf);
      println!("<Generated Hex Key>\n{}\n", buf.to_hex_string());
    }
    SubCommands::Gen_Hmac { key, algorithm, data } => {
      let data = data.as_bytes();
      let key = &hex::decode(key)?;
      let digest = match algorithm.as_str() {
        "SHA-256" => generate_hmac::<sha2::Sha256>(data, key),
        "SHA-384" => generate_hmac::<sha2::Sha384>(data, key),
        "SHA-512" => generate_hmac::<sha2::Sha512>(data, key),
        "SHA3-256" => generate_hmac::<sha3::Sha3_256>(data, key),
        "SHA3-384" => generate_hmac::<sha3::Sha3_384>(data, key),
        "SHA3-512" => generate_hmac::<sha3::Sha3_512>(data, key),
        _ => bail!("Unsupported hash algorithm: {}", algorithm),
      }?;
      println!(
        "<Computed HMAC with {}>\n{}\n",
        algorithm.as_str(),
        digest.to_hex_string()
      );
    }
    SubCommands::Verify_Hmac {
      key,
      mac,
      algorithm,
      data,
    } => {
      let data = data.as_bytes();
      let key = &hex::decode(key)?;
      let digest = match algorithm.as_str() {
        "SHA-256" => generate_hmac::<sha2::Sha256>(data, key),
        "SHA-384" => generate_hmac::<sha2::Sha384>(data, key),
        "SHA-512" => generate_hmac::<sha2::Sha512>(data, key),
        "SHA3-256" => generate_hmac::<sha3::Sha3_256>(data, key),
        "SHA3-384" => generate_hmac::<sha3::Sha3_384>(data, key),
        "SHA3-512" => generate_hmac::<sha3::Sha3_512>(data, key),
        _ => bail!("Unsupported hash algorithm: {}", algorithm),
      }?;
      println!(
        "<Verification result of given HMAC>\n{}\n",
        mac == &digest.to_hex_string()
      );
    }
    SubCommands::Gen_Rsa_key { bits } => {
      let rsa_keypair = RsaKeyPair::new(bits)?;
      println!("<Generated RSA Key Pair (DER Form)>");
      println!("Public Key:\n{}\n", rsa_keypair.to_spki_public_der()?.to_hex_string());
      println!(
        "Private Key:\n{}\n",
        rsa_keypair.to_pkcs8_private_der()?.to_hex_string()
      );
    }
    SubCommands::Sign_Rsa_Pss { private_key, data } => {
      let private_key = hex::decode(private_key)?;
      let data = data.as_bytes();
      let rsa_keypair = RsaKeyPair::from_pkcs8_private_der(&private_key)?;
      let signature = rsa_keypair.pss_sign(data)?;
      println!("<Generated RSASSA-PSS Signature>\n{}\n", signature.to_hex_string());
    }
    SubCommands::Verify_Rsa_Pss {
      public_key,
      data,
      signature,
    } => {
      let public_key = hex::decode(public_key)?;
      let data = data.as_bytes();
      let signature = hex::decode(signature)?;
      let rsa_keypair = RsaKeyPair::from_spki_public_der(&public_key)?;
      let result = rsa_keypair.pss_verify(data, &signature);
      println!("<Verification Result of RSASSA-PSS Signature>\n{}\n", result.is_ok());
    }
    SubCommands::Gen_Ecc_key { curve } => {
      let (pk, sk) = match curve.as_str() {
        "P-256" => {
          let kp = EccKeyPair::<p256::NistP256>::new();
          (kp.to_spki_public_der()?, kp.to_pkcs8_private_der()?)
        }
        "P-384" => {
          let kp = EccKeyPair::<p384::NistP384>::new();
          (kp.to_spki_public_der()?, kp.to_pkcs8_private_der()?)
        }
        _ => bail!("Unsupported curve"),
      };

      println!(
        "<Generated ECC Key Pair (DER Form)>\nPublic Key:\n{}\nPrivate Key:\n{}\n",
        pk.to_hex_string(),
        sk.to_hex_string()
      );
    }
    SubCommands::Sign_Ecdsa { private_key, data } => {
      let private_key = hex::decode(private_key)?;
      let data = data.as_bytes();
      let ecc_keypair_type = import_pkcs8_der(&private_key)?;
      let signature = match &ecc_keypair_type {
        EccKeyPairType::P256(kp) => kp.sign(data)?,
        EccKeyPairType::P384(kp) => kp.sign(data)?,
      };

      println!(
        "<Generated ECDSA Signature ({})>\n{}\n",
        ecc_keypair_type,
        signature.to_hex_string()
      );
    }
    SubCommands::Verify_Ecdsa {
      public_key,
      signature,
      data,
    } => {
      let public_key = hex::decode(public_key)?;
      let data = data.as_bytes();
      let signature = hex::decode(signature)?;
      let ecc_keypair_type = import_spki_der(&public_key)?;
      let result = match &ecc_keypair_type {
        EccKeyPairType::P256(kp) => kp.verify(data, &signature),
        EccKeyPairType::P384(kp) => kp.verify(data, &signature),
      };
      println!(
        "<Verification Result of ECDSA Signature ({})>\n{}\n",
        ecc_keypair_type,
        result.is_ok()
      );
    }
  }

  Ok(())
}
