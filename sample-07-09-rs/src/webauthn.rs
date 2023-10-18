use crate::{constants::COOKIE_REGISTRATION_STATE, log::*, startup::AppState};
use axum::{
  extract::Path,
  http::StatusCode,
  response::{IntoResponse, Response},
  Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::{ops::DerefMut, sync::Arc};
use tower_sessions::Session;
use uuid::Uuid;
use webauthn_rs::prelude::{CredentialID, PasskeyRegistration, RegisterPublicKeyCredential};

#[derive(Debug)]
pub enum WebAuthnError {
  UnknownError,
  UnknownUserLoginAttempt,
  CorruptSession,
}
impl IntoResponse for WebAuthnError {
  fn into_response(self) -> Response {
    let body = match self {
      WebAuthnError::UnknownError => "Unknown error",
      WebAuthnError::UnknownUserLoginAttempt => "Unknown user login attempt",
      WebAuthnError::CorruptSession => "Corrupt session",
    };
    (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
  }
}

#[derive(Serialize, Deserialize, Debug)]
struct RegistrationState {
  username: String,
  uuid: Uuid,
  passkey_registration: PasskeyRegistration,
}

pub async fn start_register(
  Extension(shared_state): Extension<Arc<AppState>>,
  session: Session,
  Path(username): Path<String>,
) -> Result<impl IntoResponse, WebAuthnError> {
  info!("Start register a credential for {}", username);

  let mut users = shared_state.users.lock().map_err(|e| {
    error!("Failed to lock users: {}", e);
    WebAuthnError::UnknownError
  })?;

  let uuid = *users.username_id_map.entry(username.to_owned()).or_insert_with(|| {
    let u = Uuid::new_v4();
    info!("New user registration: {} - {}", username, &u);
    u
  });
  drop(users);

  let _ = session
    .remove::<RegistrationState>(COOKIE_REGISTRATION_STATE)
    .map_err(|e| {
      error!(
        "Failed to remove registration state from session during new registration initiation: {}",
        e
      );
      WebAuthnError::UnknownError
    })?;

  let users = shared_state.users.lock().map_err(|e| {
    error!("Failed to lock users: {}", e);
    WebAuthnError::UnknownError
  })?;
  let existing_cred_ids = users.id_passkey_map.get(&uuid).map(|keys| {
    keys
      .iter()
      .map(|sk| sk.cred_id().clone())
      .collect::<Vec<CredentialID>>()
  });
  drop(users);

  let res = shared_state
    .webauthn
    .start_passkey_registration(uuid, &username, &username, existing_cred_ids);

  match res {
    Ok((ccr, passkey_registration)) => {
      info!("Registration initiated for {}", username);
      // Note that due to the session store in use being a server side memory store, this is
      // safe to store the reg_state into the session since it is not client controlled and
      // not open to replay attacks. If this was a cookie store, this would be UNSAFE.
      if let Err(e) = session.insert(
        COOKIE_REGISTRATION_STATE,
        RegistrationState {
          username,
          uuid,
          passkey_registration,
        },
      ) {
        error!(
          "Failed to insert registration state into session during new registration initiation: {}",
          e
        );
        return Err(WebAuthnError::UnknownError);
      };
      Ok(Json(ccr))
    }
    Err(e) => {
      error!("Failed to initiate registration for {}: {}", username, e);
      Err(WebAuthnError::UnknownError)
    }
  }
}

pub async fn finish_register(
  Extension(app_state): Extension<Arc<AppState>>,
  session: Session,
  Json(reg): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, WebAuthnError> {
  let reg_state = session
    .get::<RegistrationState>(COOKIE_REGISTRATION_STATE)
    .map_err(|e| {
      error!(
        "Failed to get registration state from session during registration finish: {}",
        e
      );
      WebAuthnError::UnknownError
    })?
    .ok_or(WebAuthnError::CorruptSession)?;

  let _ = session
    .remove::<RegistrationState>(COOKIE_REGISTRATION_STATE)
    .map_err(|e| {
      error!(
        "Failed to remove registration state from session during registration finish: {}",
        e
      );
      WebAuthnError::UnknownError
    })?;

  let res = app_state
    .webauthn
    .finish_passkey_registration(&reg, &reg_state.passkey_registration);

  let status_code = match res {
    Ok(new_passkey) => {
      let mut users = app_state.users.lock().map_err(|e| {
        error!("Failed to lock users: {}", e);
        WebAuthnError::UnknownError
      })?;
      let passkeys = users.id_passkey_map.entry(reg_state.uuid).or_insert(vec![]);
      passkeys.push(new_passkey.clone());
      info!("Successfully registered new credential for {}", reg_state.username);
      StatusCode::OK
    }
    Err(e) => {
      error!("Failed to register new credential for {}: {}", reg_state.username, e);
      StatusCode::BAD_REQUEST
    }
  };
  Ok(status_code)
}
