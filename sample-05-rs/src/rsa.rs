use crate::error::*;
use rsa::{
  pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
  Oaep, RsaPrivateKey, RsaPublicKey,
};

#[derive(Debug)]
pub struct RsaKeyPair {
  pub public: RsaPublicKey,
  pub private: Option<RsaPrivateKey>,
}

impl RsaKeyPair {
  pub fn new(bits: &usize) -> Result<Self> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, *bits)?;
    let public_key = private_key.to_public_key();

    Ok(Self {
      public: public_key,
      private: Some(private_key),
    })
  }

  pub fn to_spki_public_der(&self) -> Result<Vec<u8>> {
    let der = self.public.to_public_key_der()?.as_bytes().to_vec();
    Ok(der)
  }
  pub fn to_pkcs8_private_der(&self) -> Result<Vec<u8>> {
    if self.private.is_none() {
      bail!("No private key");
    }
    let der = self.private.as_ref().unwrap().to_pkcs8_der()?.as_bytes().to_vec();
    Ok(der)
  }

  pub fn from_spki_public_der(der: &[u8]) -> Result<RsaKeyPair> {
    let public_key = RsaPublicKey::from_public_key_der(der)?;
    Ok(RsaKeyPair {
      public: public_key,
      private: None,
    })
  }

  pub fn from_pkcs8_private_der(der: &[u8]) -> Result<RsaKeyPair> {
    let private_key = RsaPrivateKey::from_pkcs8_der(der)?;
    let public_key = private_key.to_public_key();
    Ok(RsaKeyPair {
      public: public_key,
      private: Some(private_key),
    })
  }

  pub fn oaep_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let padding = Oaep::new::<sha2::Sha256>();
    let enc_data = self.public.encrypt(&mut rng, padding, data)?;
    Ok(enc_data)
  }

  pub fn oaep_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
    if self.private.is_none() {
      bail!("No private key");
    }
    let padding = Oaep::new::<sha2::Sha256>();
    let dec_data = self.private.as_ref().unwrap().decrypt(padding, data)?;
    Ok(dec_data)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::util::*;

  #[test]
  fn test_keygen() {
    let keypair = RsaKeyPair::new(&2048).unwrap();

    let public_der = keypair.to_spki_public_der().unwrap();
    let private_der = keypair.to_pkcs8_private_der().unwrap();

    let keypair_from_public_der = RsaKeyPair::from_spki_public_der(&public_der).unwrap();
    let keypair_from_private_der = RsaKeyPair::from_pkcs8_private_der(&private_der).unwrap();

    let public_der2 = keypair_from_public_der.to_spki_public_der().unwrap();
    let public_der3 = keypair_from_private_der.to_spki_public_der().unwrap();
    assert_eq!(public_der, public_der2);
    assert_eq!(public_der, public_der3);

    let private_der2 = keypair_from_private_der.to_pkcs8_private_der().unwrap();
    assert_eq!(private_der, private_der2);
  }

  #[test]
  fn test_keygen_encrypt_decrypt() {
    let keypair = RsaKeyPair::new(&2048).unwrap();

    let plaintext = "hello";

    let ciphertext = keypair.oaep_encrypt(plaintext.as_bytes()).unwrap();

    let plaintext2 = String::from_utf8(keypair.oaep_decrypt(&ciphertext).unwrap()).unwrap();

    assert_eq!(plaintext.to_string(), plaintext2);
  }

  #[test]
  fn test_hex() {
    let v: [u8; 3] = [0x01, 0x02, 0x03];
    let s = v.to_vec().to_hex_string();
    assert_eq!(s, "010203")
  }
}
