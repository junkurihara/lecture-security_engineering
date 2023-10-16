mod config;
mod crypto;
mod ecc;
mod error;
mod key;
mod rsa;
mod util;

use crate::{
  crypto::{decrypt, encrypt, Encrypted},
  ecc::EccKeyPair,
  error::*,
  key::BinaryKey,
  rsa::*,
  util::*,
};
use clap::Parser;
use config::{ClapArgs, SubCommands};
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};

#[tokio::main]
pub async fn main() -> Result<()> {
  let _ = include_str!("../Cargo.toml");
  let args = ClapArgs::parse();

  match &args.subcommand {
    SubCommands::Rsa_Keygen { bits } => {
      let rsa_keypair = RsaKeyPair::new(bits)?;
      println!("<Generated RSA Key Pair (DER Form)>");
      println!("Public Key:\n{}\n", rsa_keypair.to_spki_public_der()?.to_hex_string());
      println!(
        "Private Key:\n{}\n",
        rsa_keypair.to_pkcs8_private_der()?.to_hex_string()
      );
    }
    SubCommands::Rsa_Oaep_Encrypt { public_key, data } => {
      let public_key = hex::decode(public_key)?;
      let rsa_keypair = RsaKeyPair::from_spki_public_der(&public_key)?;
      let enc_data = rsa_keypair.oaep_encrypt(data.as_bytes())?;
      println!("<Encrypted Data (in HexString)>");
      println!("{}", enc_data.to_hex_string());
    }
    SubCommands::Rsa_Oaep_Decrypt { private_key, data } => {
      let private_key = hex::decode(private_key)?;
      let data = hex::decode(data)?;
      let rsa_keypair = RsaKeyPair::from_pkcs8_private_der(&private_key)?;
      let dec_data = rsa_keypair.oaep_decrypt(&data)?;
      println!("<Decrypted Data>");
      println!("{}", String::from_utf8(dec_data)?);
    }
    SubCommands::Rsa_Oaep_Demo { data } => {
      println!("<Input Data>\n{}\n", data);
      let rsa_keypair = RsaKeyPair::new(&2048)?;
      println!(
        "<Generated RSA Key Pair (DER Form)>\nPublic Key:\n{}\nPrivate Key:\n{}\n",
        rsa_keypair.to_spki_public_der()?.to_hex_string(),
        rsa_keypair.to_pkcs8_private_der()?.to_hex_string()
      );
      let enc_data = rsa_keypair.oaep_encrypt(data.as_bytes())?;
      println!("<Encrypted Data (in HexString)>\n{}\n", enc_data.to_hex_string());
      let dec_data = rsa_keypair.oaep_decrypt(&enc_data)?;
      println!("<Decrypted Data>\n{}\n", String::from_utf8(dec_data)?);
    }
    SubCommands::Check_Ecdh => {
      let keypair1 = EccKeyPair::<p256::NistP256>::new();
      let keypair2 = EccKeyPair::<p256::NistP256>::new();
      println!(
        "<ECC Key Pair A (DER Form)>\nPublic Key:\n{}\nPrivate Key:\n{}\n",
        keypair1.to_spki_public_der()?.to_hex_string(),
        keypair1.to_pkcs8_private_der()?.to_hex_string()
      );
      println!(
        "<ECC Key Pair B (DER Form)>\nPublic Key:\n{}\nPrivate Key:\n{}\n",
        keypair2.to_spki_public_der()?.to_hex_string(),
        keypair2.to_pkcs8_private_der()?.to_hex_string()
      );
      let bits1 = keypair1.derive_bits(&keypair2)?;
      let bits2 = keypair2.derive_bits(&keypair1)?;
      println!(
        "Shared Bits from Public Key A and Private Key B: {}",
        bits2.to_hex_string()
      );
      println!(
        "Shared Bits from Public Key B and Private Key A: {}",
        bits1.to_hex_string()
      );
    }
    SubCommands::Ecc_Keygen { curve } => {
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
    SubCommands::Ecdh_Aes_Encrypt {
      public_key,
      private_key,
      data,
    } => {
      let public_key = hex::decode(public_key)?;
      let private_key = hex::decode(private_key)?;
      let data = data.as_bytes();

      let pk = EccKeyPair::<p256::NistP256>::from_spki_public_der(&public_key)? as EccKeyPair<_>;
      let sk = EccKeyPair::<p256::NistP256>::from_pkcs8_private_der(&private_key)? as EccKeyPair<_>;

      let shared_bits = sk.derive_bits(&pk)?;
      println!("<Shared Bits>\n{}\n", shared_bits.to_hex_string());

      let key = BinaryKey::try_new(&shared_bits, 32, None)?;
      println!(
        "<Derived AES Key>\nKey: {}\nHKDF-Salt: {}\nHKDF-Hash: SHA-256\n",
        key.key.to_hex_string(),
        key.salt.to_hex_string()
      );

      let enc_data = encrypt(data, &key, None)?;
      println!(
        "<Encrypted data>\nData: {}\nInitival Vector: {}\n",
        enc_data.data.to_hex_string(),
        enc_data.iv.to_hex_string()
      );

      let kdf_params = KdfParams {
        salt: key.salt.to_hex_string(),
        hash: "SHA-256".to_string(),
      };
      let encrypted_pack = EncryptedPack {
        encrypted: EncryptedHex {
          data: enc_data.data.to_hex_string(),
          iv: enc_data.iv.to_hex_string(),
        },
        kdfParams: kdf_params,
      };

      let mut buf = Vec::new();
      encrypted_pack.serialize(&mut Serializer::new(&mut buf).with_struct_map())?;

      println!("<Msgpacked encrypted and kdf data>\n{}\n", buf.to_hex_string());
    }
    SubCommands::Ecdh_Aes_Decrypt {
      public_key,
      private_key,
      data,
    } => {
      let public_key = hex::decode(public_key)?;
      let private_key = hex::decode(private_key)?;
      let data = hex::decode(data)?;

      let pk = EccKeyPair::<p256::NistP256>::from_spki_public_der(&public_key)? as EccKeyPair<_>;
      let sk = EccKeyPair::<p256::NistP256>::from_pkcs8_private_der(&private_key)? as EccKeyPair<_>;

      let shared_bits = sk.derive_bits(&pk)?;
      println!("<Shared Bits>\n{}\n", shared_bits.to_hex_string());

      let decoded = EncryptedPack::deserialize(&mut Deserializer::new(data.as_slice()))?;
      let encrypted = Encrypted {
        data: hex::decode(decoded.encrypted.data)?,
        iv: hex::decode(decoded.encrypted.iv)?,
      };
      let key = BinaryKey::try_new(&shared_bits, 32, Some(&hex::decode(decoded.kdfParams.salt)?))?;
      println!("<Derived AES Key>\n{}\n", key.key.to_hex_string());

      let decrypted = decrypt(&encrypted, &key)?;
      println!("<Decrypted data>\n{}\n", String::from_utf8(decrypted)?);
    }
  }

  Ok(())
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[allow(non_snake_case)]
struct EncryptedPack {
  encrypted: EncryptedHex,
  kdfParams: KdfParams,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[allow(non_snake_case)]
struct EncryptedHex {
  data: String,
  iv: String,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct KdfParams {
  salt: String,
  hash: String,
}
