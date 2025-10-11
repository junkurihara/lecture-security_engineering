use crate::error::*;
use crypto_common::generic_array::ArrayLength;
use ecdsa::{
  hazmat::{DigestPrimitive, VerifyPrimitive},
  signature::{Signer, Verifier},
  PrimeCurve, Signature, SignatureSize, SigningKey, VerifyingKey,
};
use elliptic_curve::{
  ecdh,
  pkcs8::{der::Decode, AssociatedOid, DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
  AffinePoint, CurveArithmetic, PublicKey, SecretKey,
  rand_core::OsRng,
};
use std::fmt::Display;

pub struct EccKeyPair<C>
where
  C: CurveArithmetic,
{
  pub public: PublicKey<C>,
  pub private: Option<SecretKey<C>>,
}

pub enum EccKeyPairType {
  P256(EccKeyPair<p256::NistP256>),
  P384(EccKeyPair<p384::NistP384>),
}
impl Display for EccKeyPairType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      EccKeyPairType::P256(_) => write!(f, "P-256"),
      EccKeyPairType::P384(_) => write!(f, "P-384"),
    }
  }
}

impl<C> EccKeyPair<C>
where
  C: CurveArithmetic + AssociatedOid + PrimeCurve + DigestPrimitive,
  AffinePoint<C>: VerifyPrimitive<C>,
  SignatureSize<C>: ArrayLength<u8>,
  <C as elliptic_curve::CurveArithmetic>::AffinePoint: elliptic_curve::sec1::FromEncodedPoint<C>,
  <C as elliptic_curve::Curve>::FieldBytesSize: elliptic_curve::sec1::ModulusSize,
  <C as elliptic_curve::CurveArithmetic>::AffinePoint: elliptic_curve::sec1::ToEncodedPoint<C>,
  <C as elliptic_curve::CurveArithmetic>::Scalar: ecdsa::hazmat::SignPrimitive<C>,
  <<C as elliptic_curve::Curve>::FieldBytesSize as std::ops::Add>::Output: ArrayLength<u8>,
{
  pub fn new() -> Self {
    let mut rng = OsRng;
    let private_key = SecretKey::random(&mut rng);
    let public_key = private_key.public_key();

    Self {
      public: public_key,
      private: Some(private_key),
    }
  }

  pub fn to_spki_public_der(&self) -> Result<Vec<u8>> {
    let der = self.public.to_public_key_der().unwrap().as_bytes().to_vec();
    Ok(der)
  }

  pub fn to_pkcs8_private_der(&self) -> Result<Vec<u8>> {
    if self.private.is_none() {
      bail!("No private key");
    }
    let der = self.private.as_ref().unwrap().to_pkcs8_der()?.as_bytes().to_vec();
    Ok(der)
  }

  pub fn from_spki_public_der(der: &[u8]) -> Result<EccKeyPair<C>> {
    let public_key = PublicKey::<C>::from_public_key_der(der)?;
    Ok(EccKeyPair {
      public: public_key,
      private: None,
    })
  }

  pub fn from_pkcs8_private_der(der: &[u8]) -> Result<EccKeyPair<C>> {
    let private_key = SecretKey::<C>::from_pkcs8_der(der)?;
    let public_key = private_key.public_key();
    Ok(EccKeyPair {
      public: public_key,
      private: Some(private_key),
    })
  }

  #[allow(dead_code)]
  pub fn derive_bits(&self, other: &EccKeyPair<C>) -> Result<Vec<u8>> {
    if self.private.is_none() && other.private.is_none() {
      bail!("No private key");
    }
    let shared_secret = match &self.private {
      Some(private_key) => ecdh::diffie_hellman(private_key.to_nonzero_scalar(), other.public.as_affine()),
      None => ecdh::diffie_hellman(
        other.private.as_ref().unwrap().to_nonzero_scalar(),
        self.public.as_affine(),
      ),
    };

    let raw_bits = shared_secret.raw_secret_bytes().as_slice();
    Ok(raw_bits.to_vec())
  }

  pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
    if self.private.is_none() {
      bail!("No private key");
    }
    let signing_key = SigningKey::from(self.private.as_ref().unwrap());
    let signature: Signature<C> = signing_key.sign(data);
    Ok(signature.to_vec())
  }

  pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
    let verifying_key = VerifyingKey::from(self.public);
    let signature: Signature<C> = Signature::try_from(signature)?;
    verifying_key.verify(data, &signature).map_err(|e| anyhow!(e))
  }
}

pub fn import_pkcs8_der(der: &[u8]) -> Result<EccKeyPairType> {
  let pki = elliptic_curve::pkcs8::PrivateKeyInfo::from_der(der)?;
  let algorithm = pki.algorithm.oid;
  let parameters = pki.algorithm.parameters_oid()?;
  match (algorithm, parameters) {
    (elliptic_curve::ALGORITHM_OID, p256::NistP256::OID) => {
      let k: EccKeyPair<p256::NistP256> = EccKeyPair::from_pkcs8_private_der(der).map_err(|e| anyhow!(e))?;
      Ok(EccKeyPairType::P256(k))
    }
    (elliptic_curve::ALGORITHM_OID, p384::NistP384::OID) => {
      let k: EccKeyPair<p384::NistP384> = EccKeyPair::from_pkcs8_private_der(der).map_err(|e| anyhow!(e))?;
      Ok(EccKeyPairType::P384(k))
    }
    _ => {
      bail!("Unsupported algorithm");
    }
  }
}

pub fn import_spki_der(der: &[u8]) -> Result<EccKeyPairType> {
  let spki = elliptic_curve::pkcs8::SubjectPublicKeyInfoRef::from_der(der)?;
  let algorithm = spki.algorithm.oid;
  let parameters = spki.algorithm.parameters_oid()?;
  match (algorithm, parameters) {
    (elliptic_curve::ALGORITHM_OID, p256::NistP256::OID) => {
      let k: EccKeyPair<p256::NistP256> = EccKeyPair::from_spki_public_der(der).map_err(|e| anyhow!(e))?;
      Ok(EccKeyPairType::P256(k))
    }
    (elliptic_curve::ALGORITHM_OID, p384::NistP384::OID) => {
      let k: EccKeyPair<p384::NistP384> = EccKeyPair::from_spki_public_der(der).map_err(|e| anyhow!(e))?;
      Ok(EccKeyPairType::P384(k))
    }
    _ => {
      bail!("Unsupported algorithm");
    }
  }
}

#[cfg(test)]
mod tests {

  use super::*;
  use crate::util::*;

  #[test]
  fn oid() {
    let keypair = EccKeyPair::<p256::NistP256>::new();
    let public_der = keypair.to_spki_public_der().unwrap();
    let private_der = keypair.to_pkcs8_private_der().unwrap();
    let k = import_pkcs8_der(&private_der).unwrap();
    assert!(matches!(k, EccKeyPairType::P256(_)));
    let k = import_spki_der(&public_der).unwrap();
    assert!(matches!(k, EccKeyPairType::P256(_)));

    let keypair = EccKeyPair::<p384::NistP384>::new();
    let public_der = keypair.to_spki_public_der().unwrap();
    let private_der = keypair.to_pkcs8_private_der().unwrap();
    let k = import_pkcs8_der(&private_der).unwrap();
    assert!(matches!(k, EccKeyPairType::P384(_)));
    let k = import_spki_der(&public_der).unwrap();
    assert!(matches!(k, EccKeyPairType::P384(_)));
  }

  #[test]
  fn test_keygen() {
    let keypair = EccKeyPair::<p256::NistP256>::new();
    let public_der = keypair.to_spki_public_der().unwrap();
    let private_der = keypair.to_pkcs8_private_der().unwrap();

    let keypair_from_public_der = EccKeyPair::<p256::NistP256>::from_spki_public_der(&public_der).unwrap();
    let keypair_from_private_der = EccKeyPair::<p256::NistP256>::from_pkcs8_private_der(&private_der).unwrap();

    let public_der2 = keypair_from_public_der.to_spki_public_der().unwrap();
    let public_der3 = keypair_from_private_der.to_spki_public_der().unwrap();
    assert_eq!(public_der, public_der2);
    assert_eq!(public_der, public_der3);

    let private_der2 = keypair_from_private_der.to_pkcs8_private_der().unwrap();
    assert_eq!(private_der, private_der2);
  }

  #[test]
  fn test_key_vector() {
    let private_key = "308193020100301306072a8648ce3d020106082a8648ce3d0301070479307702010104207922cff3b9e5910b212890ac9ff654f36c746d9549f6a57b0a513f995434453ea00a06082a8648ce3d030107a14403420004bfbfb4b020abfc135b32ace230ea5d3bc14c57c9751379d647c77128ffa0b71c4837e8185a3bdc4df8936763de63d14c935b538c9b45a2acd773b4731378f53f";
    let public_key = "3059301306072a8648ce3d020106082a8648ce3d03010703420004bfbfb4b020abfc135b32ace230ea5d3bc14c57c9751379d647c77128ffa0b71c4837e8185a3bdc4df8936763de63d14c935b538c9b45a2acd773b4731378f53f";

    let keypair_from_private_der =
      EccKeyPair::<p256::NistP256>::from_pkcs8_private_der(&hex::decode(private_key).unwrap()).unwrap();
    let keypair_from_public_der =
      EccKeyPair::<p256::NistP256>::from_spki_public_der(&hex::decode(public_key).unwrap()).unwrap();

    let public_der2 = keypair_from_public_der.to_spki_public_der().unwrap();
    let public_der3 = keypair_from_private_der.to_spki_public_der().unwrap();
    assert_eq!(hex::decode(public_key).unwrap(), public_der2);
    assert_eq!(public_der2, public_der3);
  }

  #[test]
  fn test_ecdh() {
    let keypair1 = EccKeyPair::<p256::NistP256>::new();
    let keypair2 = EccKeyPair::<p256::NistP256>::new();

    let bits1 = keypair1.derive_bits(&keypair2).unwrap();
    let bits2 = keypair2.derive_bits(&keypair1).unwrap();
    assert_eq!(bits1, bits2);
  }

  #[test]
  fn test_ecdh_vector() {
    let public_key1 = "3059301306072a8648ce3d020106082a8648ce3d03010703420004eda2be155a365f3a66aa86bb18f16afeb5ac2b77cabcc04fd77d5646d0ebe6718600914749d322ad6bcd15b955fa51866f62ed8b1c78bf2fad7788d99868c0e1";
    let private_key1 = "308193020100301306072a8648ce3d020106082a8648ce3d03010704793077020101042010f0c0660d9a51ced7218d31156b388a7442b34a3fb3f12fb0836fec5f569c31a00a06082a8648ce3d030107a14403420004eda2be155a365f3a66aa86bb18f16afeb5ac2b77cabcc04fd77d5646d0ebe6718600914749d322ad6bcd15b955fa51866f62ed8b1c78bf2fad7788d99868c0e1";

    let public_key2 = "3059301306072a8648ce3d020106082a8648ce3d03010703420004b8b4132b8191cf03f7ae3d542d7a3f201db1f1c2eecda7e3f0afff5b3a327d6e1276b531acbd05ca95005e5de077ef14f5eb714c065b913d33a5436d8b654cba";
    let private_key2 = "308193020100301306072a8648ce3d020106082a8648ce3d03010704793077020101042008c608249387c17c78ad50fe00b14929b74f7b4f729bbfee16d5aef986dc9caca00a06082a8648ce3d030107a14403420004b8b4132b8191cf03f7ae3d542d7a3f201db1f1c2eecda7e3f0afff5b3a327d6e1276b531acbd05ca95005e5de077ef14f5eb714c065b913d33a5436d8b654cba";

    let bits1 = EccKeyPair::<p256::NistP256>::from_spki_public_der(&hex::decode(public_key1).unwrap())
      .unwrap()
      .derive_bits(&EccKeyPair::<p256::NistP256>::from_pkcs8_private_der(&hex::decode(private_key2).unwrap()).unwrap())
      .unwrap();
    let bits2 = EccKeyPair::<p256::NistP256>::from_pkcs8_private_der(&hex::decode(private_key1).unwrap())
      .unwrap()
      .derive_bits(&EccKeyPair::<p256::NistP256>::from_spki_public_der(&hex::decode(public_key2).unwrap()).unwrap())
      .unwrap();
    assert_eq!(bits1, bits2);
    assert_eq!(
      "c69bed8ba4a68db213ed4d92e59d113abf6ff6cb811313abe7b7bc39c75d1602",
      &bits1.to_hex_string()
    );
  }

  #[test]
  fn test_ecdsa() {
    let keypair = EccKeyPair::<p256::NistP256>::new();
    let data = "hello".as_bytes();
    let signature = keypair.sign(data).unwrap();
    keypair.verify(data, &signature).unwrap();
  }
}
