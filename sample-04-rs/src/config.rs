use clap::{ArgAction, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ClapArgs {
  #[clap(subcommand)]
  pub subcommand: SubCommands,
}

#[allow(non_snake_case, non_camel_case_types)]
#[derive(Debug, Subcommand)]
pub enum SubCommands {
  /// Get ciphertext or plaintext object from the json server
  Get {
    /// Id number of the target data on the server
    id: usize,

    /// Password
    #[arg(short, long)]
    password: Option<String>,

    /// Master secret in base64
    #[arg(short, long)]
    master: Option<String>,

    /// Get from the preset remote server (e2e.secarchlab.net) otherwise localhost:3000
    #[arg(short, long, action = ArgAction::SetTrue)]
    remote: bool,
  },
  /// Post ciphertext or plaintext object to the json server
  Post {
    /// Plaintext data string
    data: String,

    /// Password
    #[arg(short, long)]
    password: Option<String>,

    /// Master secret in base64
    #[arg(short, long)]
    master: Option<String>,

    /// Post to the preset remote server (e2e.secarchlab.net) otherwise localhost:3000
    #[arg(short, long, action = ArgAction::SetTrue)]
    remote: bool,
  },
  /// Generate master secret
  Gen_Secret {
    /// Length of secret
    len: usize,
  },
}
