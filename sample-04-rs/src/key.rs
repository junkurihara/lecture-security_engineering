use crate::error::*;
use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
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
  pub fn try_new_pbkdf2(password: &str, len: usize, salt: Option<&str>, iter: Option<&u32>) -> Result<Self> {
    let (salt_bin, salt_base64) = match salt {
      Some(v) => (general_purpose::STANDARD.decode(v)?, v.to_string()),
      None => {
        let mut buf = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut buf);
        (buf.to_vec(), general_purpose::STANDARD.encode(buf))
      }
    };
    let iter = match iter {
      Some(v) => v,
      None => &ITERATION,
    };

    let mut key_bin = vec![Default::default(); len];

    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_bin, *iter, &mut key_bin);

    Ok(Self {
      key: key_bin,
      salt: salt_base64,
    })
  }

  pub fn try_new_hdkf(master: &str, len: usize, salt: Option<&str>) -> Result<Self> {
    let (salt_bin, salt_base64) = match salt {
      Some(v) => (general_purpose::STANDARD.decode(v)?, v.to_string()),
      None => {
        let mut buf = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut buf);
        (buf.to_vec(), general_purpose::STANDARD.encode(buf))
      }
    };
    let info = b"";
    let ikm = general_purpose::STANDARD.decode(master)?;
    let hkdf = Hkdf::<Sha256>::new(Some(&salt_bin[..]), &ikm);
    let mut okm = vec![Default::default(); len];
    hkdf.expand(info, &mut okm).map_err(|e| anyhow!(e))?;

    let key_bin: &[u8] = &okm[..];
    Ok(Self {
      key: key_bin.to_vec(),
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
    // pbkdf2
    let salt = hex!("dc04deff5a33c22df3aa82085f9c2d0f5477af73cd500dfe53162d70ba096a03").as_slice();
    let salt_base64 = general_purpose::STANDARD.encode(salt);

    let binary_key = BinaryKey::try_new_pbkdf2("password", 32, Some(&salt_base64), None)?;
    assert_eq!(
      binary_key.key.as_slice(),
      hex!("bf3d09d429fbf71bbb384a6421447da32096ff8a010c7042d3e29194237792d2")
    );
    assert_eq!(&binary_key.salt, "3ATe/1ozwi3zqoIIX5wtD1R3r3PNUA3+UxYtcLoJagM=");

    // hkdf
    let mut ikm = Vec::with_capacity(32);
    for i in 0..32 {
      ikm.push(i as u8)
    }
    let ikm_base64 = general_purpose::STANDARD.encode(&ikm);
    let salt_base64 = general_purpose::STANDARD.encode(&ikm);

    let binary_key = BinaryKey::try_new_hdkf(&ikm_base64, 144, Some(&salt_base64))?;

    let test_vector = "fJHB6pVraz09Ognk2NRFR/DKdsK0cnFQORjocdWbv6YaAV7m9LmrZhT2O8v1yBEZXBbEaqiRfV59VGWVd5L685jh6IHoZWoTN50i8JLMogXrnB/mvCSwLEMjY4dTxbHspz88XS+94aKvl/Hql9+IGfnOWNAcb6brgCEoD1rb7pmYT2FzIVk3qLWNTO2QtTl1";
    assert_eq!(
      binary_key.key.as_slice(),
      general_purpose::STANDARD.decode(test_vector)?
    );
    Ok(())
  }

  #[test]
  fn gen_binary_key_without_salt() -> Result<()> {
    let binary_key = BinaryKey::try_new_pbkdf2("password", 32, None, None)?;

    let salt = binary_key.salt;

    let binary_key_new = BinaryKey::try_new_pbkdf2("password", 32, Some(&salt), None)?;

    assert_eq!(binary_key.key, binary_key_new.key);
    assert_eq!(salt, binary_key_new.salt);
    Ok(())
  }
}
