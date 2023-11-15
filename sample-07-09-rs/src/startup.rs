use crate::{constants::*, error::*, log::*};
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
  listen_address: String,

  /// Asset directory
  #[clap(short, long, default_value = DEFAULT_ASSET_DIR)]
  asset_dir: String,

  /// RP ID
  #[clap(long, default_value = DEFAULT_RP_ID)]
  rp_id: String,

  /// RP origin which must be a valid URL
  #[clap(long, default_value = DEFAULT_RP_ORIGIN)]
  rp_origin: String,

  /// RP name
  #[clap(long, default_value = DEFAULT_RP_NAME)]
  rp_name: String,

  /// Cookie name
  #[clap(long, default_value = COOKIE_NAME)]
  cookie_name: String,
}

#[derive(Debug)]
pub struct AppState {
  pub listen_socket: SocketAddr,
  pub asset_dir: String,
  pub cookie_name: String,
  pub cookie_secure_flag: bool,

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

  let listen_socket = args.listen_address.parse::<SocketAddr>()?;
  info!("Listening on {}", &listen_socket);

  let asset_dir = args.asset_dir;
  info!("Serving static files from {}", &asset_dir);

  // webauthn
  info!("RP ID: {}", &args.rp_id);
  let rp_origin = Url::parse(&args.rp_origin).expect("Invalid URL");
  info!("RP origin: {}", rp_origin);
  info!("RP name: {}", &args.rp_name);
  let builder = WebauthnBuilder::new(&args.rp_id, &rp_origin)?;
  let builder = builder.rp_name(&args.rp_name);
  let webauthn = Arc::new(builder.build()?);

  // cookie
  let cookie_secure_flag = rp_origin.scheme() == "https";
  let cookie_name = args.cookie_name;
  info!("Cookie name: {} (secure={})", &cookie_name, cookie_secure_flag);

  // user db
  let users = Arc::new(Mutex::new(UserData {
    username_id_map: HashMap::default(),
    id_passkey_map: HashMap::default(),
  }));

  let app_state = AppState {
    listen_socket,
    asset_dir,
    cookie_secure_flag,
    cookie_name,
    webauthn,
    users,
  };
  Ok(app_state)
}
