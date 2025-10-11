use crate::error::Result;
use base64::{engine::general_purpose, Engine as _};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

const SALT_LEN: usize = 32;
const ITERATION: u32 = 2048;

pub struct BinaryKey {
  pub key: Vec<u8>,
  pub salt: String,
}

impl BinaryKey {
  pub fn try_new(password: &str, len: usize, salt: Option<&str>) -> Result<Self> {
    let (salt_bin, salt_base64) = match salt {
      Some(v) => (general_purpose::STANDARD.decode(v)?, v.to_string()),
      None => {
        let mut buf = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut buf);
        (buf.to_vec(), general_purpose::STANDARD.encode(buf))
      }
    };

    let mut key_bin = vec![Default::default(); len];

    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_bin, ITERATION, &mut key_bin);

    Ok(Self {
      key: key_bin,
      salt: salt_base64,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use hex_literal::hex;

  #[test]
  fn gen_binary_key_with_salt() -> Result<()> {
    let salt = hex!("dc04deff5a33c22df3aa82085f9c2d0f5477af73cd500dfe53162d70ba096a03").as_slice();
    let salt_base64 = general_purpose::STANDARD.encode(salt);

    let binary_key = BinaryKey::try_new("password", 32, Some(&salt_base64))?;
    assert_eq!(
      binary_key.key.as_slice(),
      hex!("bf3d09d429fbf71bbb384a6421447da32096ff8a010c7042d3e29194237792d2")
    );
    assert_eq!(&binary_key.salt, "3ATe/1ozwi3zqoIIX5wtD1R3r3PNUA3+UxYtcLoJagM=");
    Ok(())
  }

  #[test]
  fn gen_binary_key_without_salt() -> Result<()> {
    let binary_key = BinaryKey::try_new("password", 32, None)?;

    let salt = binary_key.salt;

    let binary_key_new = BinaryKey::try_new("password", 32, Some(&salt))?;

    assert_eq!(binary_key.key, binary_key_new.key);
    assert_eq!(salt, binary_key_new.salt);
    Ok(())
  }
}
