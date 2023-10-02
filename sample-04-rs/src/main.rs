mod config;
mod crypto;
mod error;
mod key;

use crate::{
  crypto::{decrypt, encrypt, Encrypted},
  error::*,
  key::BinaryKey,
};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use config::{ClapArgs, SubCommands};
use serde::{Deserialize, Serialize};

const LOCAL_SRV: &str = "http://localhost:3000/data";
const REMOTE_SRV: &str = "https://e2e.secarchlab.net/data";

#[tokio::main]
pub async fn main() -> Result<()> {
  let _ = include_str!("../Cargo.toml");
  let args = ClapArgs::parse();

  match &args.subcommand {
    SubCommands::Get { id, password, remote } => {
      get_data(id, password, remote).await?;
    }
    SubCommands::Post { data, password, remote } => {
      post_data(data, password, remote).await?;
    }
  }

  Ok(())
}

async fn post_data(data: &str, key: &str, remote: &bool) -> Result<()> {
  if *remote {
    println!("Register encrypted data to remote server");
  }
  println!("Data: {data}");
  println!("Password: {key}");

  let binary_key = BinaryKey::try_new(key, 32, None)?;
  let encrypted = encrypt(data.as_bytes(), &binary_key, None)?;
  let data = encrypted.data_to_base64();
  let iv = encrypted.iv_to_base64();

  println!("Derived key and its related params:");
  println!(
    "Derived key in Base64: {}",
    general_purpose::STANDARD.encode(&binary_key.key)
  );
  println!("PBKDF2 Param - Salt in Base64: {}", binary_key.salt);
  println!("PBKDF2 Param - Hash: SHA-256");
  println!("PBKDF2 Param - Iteration: 2048");

  let body = PostRequest {
    data,
    iv,
    kdfParams: KdfParams {
      salt: binary_key.salt,
      hash: "SHA-256".to_string(),
      iternationCount: 2048,
    },
  };

  let client = reqwest::Client::new();
  let srv = if *remote { REMOTE_SRV } else { LOCAL_SRV };
  let res = client.post(srv).json::<PostRequest>(&body).send().await?;
  let post_res = res.json::<PostResponse>().await?;

  println!("Registered id: {:?}", post_res.id);

  Ok(())
}

async fn get_data(id: &usize, key: &str, remote: &bool) -> Result<()> {
  if *remote {
    println!("Retrieve encrypted data to remote server");
  }
  println!("Id: {id}");
  println!("Password: {key}");

  let client = reqwest::Client::new();
  let srv = if *remote { REMOTE_SRV } else { LOCAL_SRV };
  let res = client.get(format!("{srv}/{id}")).send().await?;
  let get_res = res.json::<GetResponse>().await?;

  let binary_data = general_purpose::STANDARD.decode(get_res.data)?;
  let salt = get_res.kdfParams.salt;
  let hash = get_res.kdfParams.hash;
  let iter = get_res.kdfParams.iternationCount;
  let iv = get_res.iv;
  let binary_key = BinaryKey::try_new(key, 32, Some(&salt))?;
  let binary_iv = general_purpose::STANDARD.decode(iv)?;

  println!("Derived key and its related params:");
  println!(
    "Derived key in Base64: {}",
    general_purpose::STANDARD.encode(&binary_key.key)
  );
  println!("PBKDF2 Param - Salt in Base64: {}", binary_key.salt);
  println!("PBKDF2 Param - Hash: {hash}");
  println!("PBKDF2 Param - Iteration: {iter}");

  let dec = decrypt(
    &Encrypted {
      data: binary_data,
      iv: binary_iv,
    },
    &binary_key,
  )?;

  println!("Decrypted data: {}", String::from_utf8(dec)?);
  Ok(())
}

#[allow(non_snake_case)]
#[derive(Serialize, Debug)]
struct PostRequest {
  pub data: String,
  pub iv: String,
  pub kdfParams: KdfParams,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct KdfParams {
  salt: String,
  hash: String,
  iternationCount: usize,
}

#[derive(Deserialize, Debug)]
struct PostResponse {
  pub id: usize,
}

#[allow(non_snake_case)]
#[derive(Deserialize, Debug)]
struct GetResponse {
  #[allow(dead_code)]
  pub id: usize,
  pub data: String,
  pub iv: String,
  pub kdfParams: KdfParams,
}
