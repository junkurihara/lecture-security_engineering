mod constants;
mod error;
mod log;
mod startup;
mod webauthn;

use crate::{constants::COOKIE_NAME, error::*, log::*, startup::*, webauthn::*};
use axum::{
  error_handling::HandleErrorLayer, extract::Extension, http::StatusCode, routing::post, BoxError, Router, Server,
};
use std::sync::Arc;
use tokio::runtime::Builder;
use tower::ServiceBuilder;
use tower_http::services::ServeDir;
use tower_sessions::{cookie::SameSite, MemoryStore, SessionManagerLayer};

fn main() -> Result<()> {
  init_logger();

  let mut runtime_builder = Builder::new_multi_thread();
  runtime_builder.enable_all();
  runtime_builder.thread_name("webauthn_sample");
  let runtime = runtime_builder.build().unwrap();

  runtime.block_on(async {
    match parse_opts().await {
      Ok(shared_state) => {
        define_route(Arc::new(shared_state)).await;
      }
      Err(e) => {
        error!("{e}");
      }
    };
  });

  Ok(())
}

async fn define_route(shared_state: Arc<AppState>) {
  let addr = shared_state.listen_socket;

  info!("Listening on {}", &addr);

  // session
  let session_store = MemoryStore::default();
  let session_service = ServiceBuilder::new()
    .layer(HandleErrorLayer::new(|_: BoxError| async { StatusCode::BAD_REQUEST }))
    .layer(
      SessionManagerLayer::new(session_store)
        .with_secure(false) // TODO: This should be true in production
        .with_name(COOKIE_NAME)
        .with_same_site(SameSite::Lax),
    );

  // routes
  let api = Router::new()
    .route("/register_start/:username", post(start_register))
    .layer(Extension(shared_state));
  let static_files = Router::new().nest_service("/", ServeDir::new("./assets").append_index_html_on_directories(true));

  // build router with session
  let router = Router::new().merge(api).merge(static_files).layer(session_service);

  // build server
  let server = Server::bind(&addr).serve(router.into_make_service());

  if let Err(e) = server.await {
    error!("Server is down!: {e}");
  }
}
