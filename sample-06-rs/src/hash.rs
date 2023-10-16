use crate::error::*;
use crypto_common::{typenum::IsLess, BlockSizeUser};
use digest::{
  block_buffer::Eager,
  core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
  Digest, HashMarker, Mac,
};
use hmac::Hmac;
use typenum::{Le, NonZero, U256};

pub fn generate_hash<D>(data: &[u8]) -> Vec<u8>
where
  D: Digest,
{
  let mut hasher = D::new();
  hasher.update(data);
  hasher.finalize().to_vec()
}

pub fn generate_hmac<D>(data: &[u8], key: &[u8]) -> Result<Vec<u8>>
where
  D: CoreProxy,
  D::Core: HashMarker + UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
  <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
  Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
  let mut mac = Hmac::<D>::new_from_slice(key)?;
  mac.update(data);

  // `result` has type `CtOutput` which is a thin wrapper around array of
  // bytes for providing constant time equality check
  Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
  use super::*;
  use hex_literal::hex;
  use sha2::{Sha256, Sha384, Sha512};
  use sha3::{Sha3_256, Sha3_384, Sha3_512};

  #[test]
  fn test_generate_hash() {
    let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();

    assert_eq!(
      generate_hash::<Sha256>(data),
      hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    );
    assert_eq!(
      generate_hash::<Sha384>(data),
      hex!("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b")
    );
    assert_eq!(
      generate_hash::<Sha512>(data),
      hex!("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445")
    );
    assert_eq!(
      generate_hash::<Sha3_256>(data),
      hex!("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376")
    );
    assert_eq!(
      generate_hash::<Sha3_384>(data),
      hex!("991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22")
    );
    assert_eq!(
      generate_hash::<Sha3_512>(data),
      hex!("04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e")
    );
  }

  #[test]
  fn test_generate_hmac() {
    let key = "luchse sind halt tolle katzen".as_bytes();
    let data = "luchse luchsen luchsig in luxemburg umher".as_bytes();

    assert_eq!(
      generate_hmac::<Sha256>(data, key).unwrap(),
      hex!("2ce4f6d7e9ac3abc656a8db6ed66df72d6beed9b310f6fc2cffe57db7631c88f")
    );
    assert_eq!(
      generate_hmac::<Sha384>(data, key).unwrap(),
      hex!("9fe725ff6a9b0f898028cc5232e35b0370974087fcef3e3c733721bf2d0eb7f99b12437458c6b5a77af74db886c744ab")
    );
    assert_eq!(generate_hmac::<Sha512>(data, key).unwrap(), hex!("dfaccb94cb57c9c48a22b7a72931e581ba9ef0c3b9fad37abe80a3091ea8d9bf0b37236e6be9e53ef27ad57f10c335d28e3ffdcfb92fd23a7f5e409993b97887"));
    assert_eq!(
      generate_hmac::<Sha3_256>(data, key).unwrap(),
      hex!("3f8c691e77be447d4ecdcf0d61f28b9c8c0067f6fdd822464b9da369f3c2852b")
    );
    assert_eq!(
      generate_hmac::<Sha3_384>(data, key).unwrap(),
      hex!("152d19cf3538989b1cd1685d94c6f4705fa975c20d2cefca541291c5a401fb5cf977640aa421b92621f53664789355a7")
    );
    assert_eq!(generate_hmac::<Sha3_512>(data, key).unwrap(), hex!("6379a3fdebee97d298ba4a1ac63379e81e90b70277ec2770c48f841777789bee5c1f49c33812af4ac5d478413e5c0ffe89dabbea5f46c9f3acdb8952992b9202"));
  }
}
