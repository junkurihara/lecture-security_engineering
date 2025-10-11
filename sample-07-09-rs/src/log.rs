#[allow(unused)]
pub use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init_logger() {
  let format_layer = fmt::layer()
    .with_line_number(false)
    .with_thread_ids(false)
    .with_target(false)
    .with_thread_names(true)
    .with_target(true)
    .with_level(true)
    .compact();

  // This limits the logger to emits only this crate
  let level_string = std::env::var(EnvFilter::DEFAULT_ENV).unwrap_or_else(|_| "info".to_string());
  let filter_layer = EnvFilter::new(format!("{}={}", env!("CARGO_PKG_NAME"), level_string));

  tracing_subscriber::registry()
    .with(format_layer)
    .with(filter_layer)
    .init();
}
