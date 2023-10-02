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
    SubCommands::Get {
      id,
      password,
      master,
      remote,
    } => {
      get_data(
        id,
        password.as_ref().map(|x| x.as_str()),
        master.as_ref().map(|x| x.as_str()),
        remote,
      )
      .await?;
    }
    SubCommands::Post {
      data,
      password,
      master,
      remote,
    } => {
      post_data(
        data,
        password.as_ref().map(|x| x.as_str()),
        master.as_ref().map(|x| x.as_str()),
        remote,
      )
      .await?;
    }
    SubCommands::Gen_Secret { len } => {
      use rand::RngCore;
      let mut buf: Vec<u8> = vec![Default::default(); *len];
      rand::thread_rng().fill_bytes(&mut buf);
      let sec_b64 = general_purpose::STANDARD.encode(buf);
      println!("Generated master secret in Base64: {sec_b64}");
    }
  }

  Ok(())
}

async fn post_data(data: &str, pass: Option<&str>, master: Option<&str>, remote: &bool) -> Result<()> {
  if *remote {
    println!("Register encrypted data to remote server");
  }
  if (pass.is_none() && master.is_none()) && (pass.is_some() && master.is_some()) {
    bail!("Either one of password or master must be exclusively specified");
  }
  println!("Data: {data}");

  let body = if pass.is_some() {
    println!("Password: {}", pass.unwrap());

    let binary_key = BinaryKey::try_new_pbkdf2(pass.unwrap(), 32, None, None)?;
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

    PostRequest {
      data,
      iv,
      kdfParams: KdfParams {
        salt: binary_key.salt,
        hash: "SHA-256".to_string(),
        iterationCount: Some(2048),
      },
    }
  } else {
    println!("Master secret: {}", master.unwrap());
    let binary_key = BinaryKey::try_new_hdkf(master.unwrap(), 32, None)?;
    let encrypted = encrypt(data.as_bytes(), &binary_key, None)?;
    let data = encrypted.data_to_base64();
    let iv = encrypted.iv_to_base64();

    println!("Derived key and its related params:");
    println!(
      "Derived key in Base64: {}",
      general_purpose::STANDARD.encode(&binary_key.key)
    );
    println!("HKDF Param - Salt in Base64: {}", binary_key.salt);
    println!("HKDF Param - Hash: SHA-256");

    PostRequest {
      data,
      iv,
      kdfParams: KdfParams {
        salt: binary_key.salt,
        hash: "SHA-256".to_string(),
        iterationCount: None,
      },
    }
  };

  let client = reqwest::Client::new();
  let srv = if *remote { REMOTE_SRV } else { LOCAL_SRV };
  let res = client.post(srv).json::<PostRequest>(&body).send().await?;
  let post_res = res.json::<PostResponse>().await?;

  println!("Registered id: {:?}", post_res.id);

  Ok(())
}

async fn get_data(id: &usize, pass: Option<&str>, master: Option<&str>, remote: &bool) -> Result<()> {
  if *remote {
    println!("Retrieve encrypted data to remote server");
  }
  if (pass.is_none() && master.is_none()) && (pass.is_some() && master.is_some()) {
    bail!("Either one of password or master must be exclusively specified");
  }
  println!("Id: {id}");

  let client = reqwest::Client::new();
  let srv = if *remote { REMOTE_SRV } else { LOCAL_SRV };
  let res = client.get(format!("{srv}/{id}")).send().await?;
  let get_res = res.json::<GetResponse>().await?;
  let binary_data = general_purpose::STANDARD.decode(get_res.data)?;
  let binary_iv = general_purpose::STANDARD.decode(get_res.iv)?;
  let kdf_params = get_res.kdfParams;

  let binary_key = if pass.is_some() {
    println!("{:?}", kdf_params);
    ensure!(
      kdf_params.iterationCount.is_some(),
      "Invalid KDF params. Maybe key was derived with HDKF."
    );
    println!("Password: {}", pass.unwrap());
    let iter = kdf_params.iterationCount.unwrap();
    let k = BinaryKey::try_new_pbkdf2(pass.unwrap(), 32, Some(&kdf_params.salt), None)?;
    println!("Derived key and its related params:");
    println!("Derived key in Base64: {}", general_purpose::STANDARD.encode(&k.key));
    println!("PBKDF2 Param - Salt in Base64: {}", k.salt);
    println!("PBKDF2 Param - Hash: {}", kdf_params.hash);
    println!("PBKDF2 Param - Iteration: {}", iter);
    k
  } else {
    println!("Master secret: {}", master.unwrap());
    ensure!(
      kdf_params.iterationCount.is_none(),
      "Invalid KDF params. Maybe key was derived with PBKDF."
    );
    let k = BinaryKey::try_new_hdkf(master.unwrap(), 32, Some(&kdf_params.salt))?;
    println!("Derived key and its related params:");
    println!("Derived key in Base64: {}", general_purpose::STANDARD.encode(&k.key));
    println!("HKDF Param - Salt in Base64: {}", k.salt);
    println!("HKDF Param - Hash: {}", kdf_params.hash);
    k
  };

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
  iterationCount: Option<usize>,
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
