use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{USER_TAG, extractors::PermissionExtractor, models::user::User, state::AppState};

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct CreateUserBody {
    name: String,
    password: String,
}

#[derive(Debug, Clone, ToSchema, Serialize)]
pub struct CreateUserResponse {
    user_name: String,
}

#[utoipa::path(
    method(post),
    tag = USER_TAG,
    path = "/api/user",
    description = "Only admin can call",
    request_body = CreateUserBody,
    responses(
        (status = OK, description = "Success", body = CreateUserResponse, content_type = "application/json")
    ),
    security(("docker_basic" = []))
)]
pub async fn create_user(
    State(state): State<AppState>,
    PermissionExtractor { user, .. }: PermissionExtractor,
    Json(body): Json<CreateUserBody>,
) -> crate::Result<Json<CreateUserResponse>> {
    use argon2::PasswordHasher;
    super::verify_admin(&user)?;

    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon = argon2::Argon2::default();
    let pw_hash = argon.hash_password(body.password.as_bytes(), &salt)?;

    let user = User::new_user(body.name);
    user.insert(state.db()).await?;
    user.add_hash(&pw_hash.to_string(), state.db()).await?;

    Ok(Json(CreateUserResponse {
        user_name: user.name,
    }))
}
