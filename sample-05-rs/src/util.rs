pub trait ToHexString {
  fn to_hex_string(&self) -> String;
}

impl ToHexString for Vec<u8> {
  fn to_hex_string(&self) -> String {
    self.iter().fold("".to_string(), |acc, n| format!("{}{:02x}", acc, n))
  }
}

impl ToHexString for &[u8] {
  fn to_hex_string(&self) -> String {
    self.iter().fold("".to_string(), |acc, n| format!("{}{:02x}", acc, n))
  }
}
