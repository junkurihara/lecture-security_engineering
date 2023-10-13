use crate::error::*;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

const SALT_LEN: usize = 32;

pub struct BinaryKey {
  pub key: Vec<u8>,
  pub salt: Vec<u8>,
}

impl BinaryKey {
  pub fn try_new(master: &[u8], len: usize, salt: Option<&[u8]>) -> Result<Self> {
    let salt_bin = match salt {
      Some(v) => v.to_vec(),
      None => {
        let mut buf = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut buf);
        buf.to_vec()
      }
    };
    let info = b"";
    let hkdf = Hkdf::<Sha256>::new(Some(&salt_bin), master);
    let mut okm = vec![Default::default(); len];
    hkdf.expand(info, &mut okm).map_err(|e| anyhow!(e))?;

    Ok(Self {
      key: okm.to_vec(),
      salt: salt_bin.to_vec(),
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use base64::{engine::general_purpose, Engine as _};

  #[test]
  fn gen_binary_key_with_salt() -> Result<()> {
    // hkdf
    let mut ikm = Vec::with_capacity(32);
    for i in 0..32 {
      ikm.push(i as u8)
    }

    let binary_key = BinaryKey::try_new(&ikm, 144, Some(&ikm))?;

    let test_vector = "fJHB6pVraz09Ognk2NRFR/DKdsK0cnFQORjocdWbv6YaAV7m9LmrZhT2O8v1yBEZXBbEaqiRfV59VGWVd5L685jh6IHoZWoTN50i8JLMogXrnB/mvCSwLEMjY4dTxbHspz88XS+94aKvl/Hql9+IGfnOWNAcb6brgCEoD1rb7pmYT2FzIVk3qLWNTO2QtTl1";
    assert_eq!(
      binary_key.key.as_slice(),
      general_purpose::STANDARD.decode(test_vector)?
    );
    Ok(())
  }
}
