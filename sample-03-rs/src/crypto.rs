use crate::{error::*, key::BinaryKey};
use aes::cipher::{
  block_padding::Pkcs7,
  generic_array::{
    typenum::{U16, U32},
    GenericArray,
  },
  BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub struct Encrypted {
  pub data: Vec<u8>,
  pub iv: Vec<u8>,
}

impl Encrypted {
  #[allow(dead_code)]
  pub fn data_to_base64(&self) -> String {
    general_purpose::STANDARD.encode(&self.data)
  }
  #[allow(dead_code)]
  pub fn iv_to_base64(&self) -> String {
    general_purpose::STANDARD.encode(&self.iv)
  }
}

pub fn encrypt(data: &[u8], key: &BinaryKey, iv: Option<&[u8]>) -> Result<Encrypted> {
  let key_array: &GenericArray<u8, U32> = GenericArray::from_slice(&key.key);
  let iv = match iv {
    None => {
      let mut iv = [0u8; 16];
      rand::rng().fill_bytes(&mut iv);
      iv.to_vec()
    }
    Some(v) => v.to_vec(),
  };
  let iv: &GenericArray<u8, U16> = GenericArray::from_slice(&iv);

  let encrypted = Aes256CbcEnc::new(key_array, iv).encrypt_padded_vec_mut::<Pkcs7>(data);

  Ok(Encrypted {
    data: encrypted,
    iv: iv.to_vec(),
  })
}

pub fn decrypt(encrypted: &Encrypted, key: &BinaryKey) -> Result<Vec<u8>> {
  let key_array: &GenericArray<u8, U32> = GenericArray::from_slice(&key.key);
  let iv: &GenericArray<u8, U16> = GenericArray::from_slice(&encrypted.iv);
  Aes256CbcDec::new(key_array, iv)
    .decrypt_padded_vec_mut::<Pkcs7>(&encrypted.data)
    .map_err(|e| anyhow!(e))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn aes_cbc_works() -> Result<()> {
    let data = b"secret".as_slice();
    let key = BinaryKey::try_new("password", 32, None)?;
    let encrypted = encrypt(data, &key, None)?;
    let decrypted = decrypt(&encrypted, &key)?;

    assert_eq!(&decrypted, data);
    Ok(())
  }

  #[test]
  fn aes_cbc_test_vector() -> Result<()> {
    let data = b"hello my super secret world!!!";
    let key = BinaryKey::try_new(
      "my secret key",
      32,
      Some("jbfL016yS9RUb8Sf+6m+Pm2L1Io7u1SpqHsr+R6RTu4="),
    )?;
    let iv = general_purpose::STANDARD.decode("zuwTPW7nrWon6nEhyrzzxA==")?;
    let encrypted_data = general_purpose::STANDARD.decode("EoeSsv5BFr6s1jZh3iMM1Pxa+wA4UxQnM30J2027kJU=")?;

    let encrypted = encrypt(data, &key, Some(&iv))?;

    assert_eq!(encrypted.data, encrypted_data);
    assert_eq!(iv, encrypted.iv);

    let dec = decrypt(
      &Encrypted {
        data: encrypted_data,
        iv,
      },
      &key,
    )?;

    assert_eq!(data.as_slice(), &dec);
    Ok(())
  }
}
