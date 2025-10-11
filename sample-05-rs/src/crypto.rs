use crate::{error::*, key::BinaryKey};
use aes::cipher::{
  block_padding::Pkcs7,
  generic_array::{
    typenum::{U16, U32},
    GenericArray,
  },
  BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use rand::RngCore;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub struct Encrypted {
  pub data: Vec<u8>,
  pub iv: Vec<u8>,
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
    let key = BinaryKey::try_new("password".as_bytes(), 32, None)?;
    let encrypted = encrypt(data, &key, None)?;
    let decrypted = decrypt(&encrypted, &key)?;

    assert_eq!(&decrypted, data);
    Ok(())
  }

  #[test]
  fn aes_cbc_test_vector() -> Result<()> {
    let data = b"hello my super secret world!!!";
    let salt = hex::decode("8db7cbd35eb24bd4546fc49ffba9be3e6d8bd48a3bbb54a9a87b2bf91e914eee")?;
    let key = BinaryKey::try_new(b"my secret key", 32, Some(&salt))?;

    let iv = hex::decode("ceec133d6ee7ad6a27ea7121cabcf3c4")?;
    let encrypted_data = hex::decode("ea581e08b09f990ea4b68cb5fc119e773fb4103399cb15c6f5991b50daafe6e0")?;

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

    assert_eq!(data, dec.as_slice());
    Ok(())
  }
}
