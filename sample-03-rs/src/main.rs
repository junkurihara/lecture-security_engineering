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
use serde::Deserialize;
use std::collections::HashMap;

const LOCAL_SRV: &str = "http://localhost:3000/data";
const REMOTE_SRV: &str = "https://e2e.secarchlab.net/data";

#[tokio::main]
pub async fn main() -> Result<()> {
  let _ = include_str!("../Cargo.toml");
  let args = ClapArgs::parse();

  match &args.subcommand {
    SubCommands::Get {
      id,
      key,
      decrypt,
      remote,
    } => {
      if (key.is_none() && *decrypt) || (key.is_some() && !*decrypt) {
        bail!("when -d is specified, -k must be simultaneously specified")
      }
      get_data(id, key.as_ref().map(|x| x.as_str()), remote).await?;
    }
    SubCommands::Post {
      data,
      key,
      encrypt,
      remote,
    } => {
      if (key.is_none() && *encrypt) || (key.is_some() && !*encrypt) {
        bail!("when -e is specified, -k must be simultaneously specified")
      }
      post_data(data, key.as_ref().map(|x| x.as_str()), remote).await?;
    }
  }

  Ok(())
}

async fn post_data(data: &str, key: Option<&str>, remote: &bool) -> Result<()> {
  let mut body = HashMap::new();
  match key {
    Some(key) => {
      println!("Encrypt data");
      let binary_key = BinaryKey::try_new(key, 32, None)?;
      let encrypted = encrypt(data.as_bytes(), &binary_key, None)?;
      let data = encrypted.data_to_base64();
      let iv = encrypted.iv_to_base64();
      body.insert("data", data);
      body.insert("iv", iv);
      body.insert("salt", binary_key.salt);
    }
    None => {
      body.insert("data", data.to_string());
    }
  }

  let client = reqwest::Client::new();
  let srv = if *remote { REMOTE_SRV } else { LOCAL_SRV };
  let res = client.post(srv).json(&body).send().await?;
  let post_res = res.json::<PostResponse>().await?;
  println!("Registered id: {:?}", post_res.id);

  Ok(())
}

async fn get_data(id: &usize, key: Option<&str>, remote: &bool) -> Result<()> {
  let client = reqwest::Client::new();
  let srv = if *remote { REMOTE_SRV } else { LOCAL_SRV };
  let res = client.get(format!("{srv}/{id}")).send().await?;
  let get_res = res.json::<GetResponse>().await?;

  let retrieved_data = match (key, get_res.salt, get_res.iv) {
    (Some(key), Some(salt), Some(iv)) => {
      println!("Decrypt data");
      let binary_data = general_purpose::STANDARD.decode(get_res.data)?;
      let binary_key = BinaryKey::try_new(key, 32, Some(&salt))?;
      let binary_iv = general_purpose::STANDARD.decode(iv)?;
      let dec = decrypt(
        &Encrypted {
          data: binary_data,
          iv: binary_iv,
        },
        &binary_key,
      )?;
      String::from_utf8(dec)?
    }
    (None, None, None) => get_res.data,
    _ => {
      bail!("Invalid data format or ungiven key for the id: {}", get_res.id)
    }
  };
  println!("Retrieved data: {retrieved_data}");
  Ok(())
}

#[derive(Deserialize, Debug)]
struct PostResponse {
  pub id: usize,
}

#[derive(Deserialize, Debug)]
struct GetResponse {
  pub id: usize,
  pub data: String,
  pub iv: Option<String>,
  pub salt: Option<String>,
}
