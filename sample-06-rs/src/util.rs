pub trait ToHexString {
  fn to_hex_string(&self) -> String;
}

impl ToHexString for Vec<u8> {
  fn to_hex_string(&self) -> String {
    hex::encode(self)
  }
}

impl ToHexString for &[u8] {
  fn to_hex_string(&self) -> String {
    hex::encode(self)
  }
}
