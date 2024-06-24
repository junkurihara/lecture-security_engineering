use crate::{
  constants::{COOKIE_AUTHENTICATION_STATE, COOKIE_REGISTRATION_STATE},
  log::*,
  startup::AppState,
};
use axum::{
  extract::Path,
  http::StatusCode,
  response::{IntoResponse, Response},
  Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_sessions::Session;
use uuid::Uuid;
use webauthn_rs::prelude::{
  //AttestationCaList,
  CredentialID,
  PasskeyAuthentication,
  PasskeyRegistration,
  PublicKeyCredential,
  RegisterPublicKeyCredential,
};

#[derive(Debug)]
pub enum WebAuthnError {
  UnknownError,
  UnknownUserLoginAttempt,
  NoCredential,
  CorruptSession,
}
impl IntoResponse for WebAuthnError {
  fn into_response(self) -> Response {
    let body = match self {
      WebAuthnError::UnknownError => "Unknown error",
      WebAuthnError::UnknownUserLoginAttempt => "Unknown user login attempt",
      WebAuthnError::NoCredential => "No credential",
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

#[derive(Serialize, Deserialize, Debug)]
struct AuthenticationState {
  username: String,
  uuid: Uuid,
  passkey_authentication: PasskeyAuthentication,
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

  let _ = session.remove::<RegistrationState>(COOKIE_REGISTRATION_STATE).map_err(|e| {
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
  let existing_cred_ids = users
    .id_passkey_map
    .get(&uuid)
    .map(|keys| keys.iter().map(|sk| sk.cred_id().clone()).collect::<Vec<CredentialID>>());
  drop(users);

  let res = shared_state
    .webauthn
    .start_passkey_registration(uuid, &username, &username, existing_cred_ids);
  // .start_passkey_registration(uuid, &username, &username, existing_cred_ids);

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

  let _ = session.remove::<RegistrationState>(COOKIE_REGISTRATION_STATE).map_err(|e| {
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

pub async fn start_auth(
  Extension(shared_state): Extension<Arc<AppState>>,
  session: Session,
  Path(username): Path<String>,
) -> Result<impl IntoResponse, WebAuthnError> {
  info!("Start authentication for {}", username);

  let _ = session
    .remove::<AuthenticationState>(COOKIE_AUTHENTICATION_STATE)
    .map_err(|e| {
      error!(
        "Failed to remove authentication state from session during new authentication initiation: {}",
        e
      );
      WebAuthnError::UnknownError
    })?;

  let users = shared_state.users.lock().map_err(|e| {
    error!("Failed to lock users: {}", e);
    WebAuthnError::UnknownError
  })?;

  let uuid = *users
    .username_id_map
    .get(&username)
    .ok_or(WebAuthnError::UnknownUserLoginAttempt)?;
  let creds = users.id_passkey_map.get(&uuid).ok_or(WebAuthnError::NoCredential)?;

  let res = shared_state.webauthn.start_passkey_authentication(creds.as_slice());

  drop(users);

  match res {
    Ok((rcr, passkey_authentication)) => {
      info!("Authentication initiated for {}", username);
      if let Err(e) = session.insert(
        COOKIE_AUTHENTICATION_STATE,
        AuthenticationState {
          username,
          uuid,
          passkey_authentication,
        },
      ) {
        error!(
          "Failed to insert authentication state into session during new authentication initiation: {}",
          e
        );
        return Err(WebAuthnError::UnknownError);
      };
      Ok(Json(rcr))
    }
    Err(e) => {
      error!("Failed to initiate authentication for {}: {}", username, e);
      Err(WebAuthnError::UnknownError)
    }
  }
}

pub async fn finish_auth(
  Extension(shared_state): Extension<Arc<AppState>>,
  session: Session,
  Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, WebAuthnError> {
  let auth_state = session
    .get::<AuthenticationState>(COOKIE_AUTHENTICATION_STATE)
    .map_err(|e| {
      error!(
        "Failed to get authentication state from session during authentication finish: {}",
        e
      );
      WebAuthnError::UnknownError
    })?
    .ok_or(WebAuthnError::CorruptSession)?;

  let _ = session
    .remove::<AuthenticationState>(COOKIE_AUTHENTICATION_STATE)
    .map_err(|e| {
      error!(
        "Failed to remove authentication state from session during authentication finish: {}",
        e
      );
      WebAuthnError::UnknownError
    })?;

  let res = shared_state
    .webauthn
    .finish_passkey_authentication(&auth, &auth_state.passkey_authentication);

  let status_code = match res {
    Ok(auth_res) => {
      let mut users = shared_state.users.lock().map_err(|e| {
        error!("Failed to lock users: {}", e);
        WebAuthnError::UnknownError
      })?;

      // Update the credential counter, if possible.
      users
        .id_passkey_map
        .get_mut(&auth_state.uuid)
        .map(|keys| {
          keys.iter_mut().for_each(|sk| {
            // This will update the credential if it's the matching
            // one. Otherwise it's ignored. That is why it is safe to
            // iterate this over the full list.
            sk.update_credential(&auth_res);
          })
        })
        .ok_or(WebAuthnError::NoCredential)?;
      info!("Successfully authenticated for {}", auth_state.username);
      StatusCode::OK
    }
    Err(e) => {
      error!("Failed to authenticate for {}: {}", auth_state.username, e);
      StatusCode::BAD_REQUEST
    }
  };
  Ok(status_code)
}
