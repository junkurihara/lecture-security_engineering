use crate::{constants::*, error::*};
use clap::Parser;
use rustc_hash::FxHashMap as HashMap;
use std::{
  net::SocketAddr,
  sync::{Arc, Mutex},
};
use url::Url;
use uuid::Uuid;
use webauthn_rs::{prelude::PasswordlessKey, Webauthn, WebauthnBuilder};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ClapArgs {
  /// Listen socket
  #[clap(short, long, default_value = DEFAULT_LISTEN_ADDR)]
  listen_addr: String,

  /// Asset directory
  #[clap(short, long, default_value = DEFAULT_ASSET_DIR)]
  asset_dir: String,
}

#[derive(Debug)]
pub struct AppState {
  pub listen_socket: SocketAddr,
  pub asset_dir: String,

  pub webauthn: Arc<Webauthn>,

  pub users: Arc<Mutex<UserData>>,
}

#[derive(Debug)]
pub struct UserData {
  pub username_id_map: HashMap<String, Uuid>,
  pub id_passkey_map: HashMap<Uuid, Vec<PasswordlessKey>>,
}

pub async fn parse_opts() -> Result<AppState> {
  let _ = include_str!("../Cargo.toml");
  let args = ClapArgs::parse();

  let listen_socket = args.listen_addr.parse::<SocketAddr>()?;
  let asset_dir = args.asset_dir;

  // webauthn
  // TODO: These should be overridden by command line arguments
  let rp_id = DEFAULT_RP_ID;
  let rp_origin = Url::parse(DEFAULT_RP_ORIGIN).expect("Invalid URL");
  let builder = WebauthnBuilder::new(rp_id, &rp_origin)?;
  let builder = builder.rp_name(DEFAULT_RP_NAME);
  let webauthn = Arc::new(builder.build()?);

  // user db
  let users = Arc::new(Mutex::new(UserData {
    username_id_map: HashMap::default(),
    id_passkey_map: HashMap::default(),
  }));

  let app_state = AppState {
    listen_socket,
    asset_dir,
    webauthn,
    users,
  };
  Ok(app_state)
}
