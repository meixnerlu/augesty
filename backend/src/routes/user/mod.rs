mod user;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
pub use user::*;
mod svc;
pub use svc::*;
use utoipa::ToSchema;

use crate::{extractors::PermissionExtractor, models::user::User, state::AppState, USER_TAG};

pub(self) fn verify_admin(user: &User) -> crate::Result<()> {
    if user.name != "admin" {
        return Err(crate::Error::Unauthorized("Only admin can manage users"));
    }
    Ok(())
}

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct GrantAccessBody {
    name: String,
    image: String,
    access: String,
}

#[derive(Debug, Clone, ToSchema, Serialize)]
pub struct GrantAccessResponse {
    user_name: String
}

#[utoipa::path(
    method(post),
    tag = USER_TAG,
    path = "/api/user/access",
    description = "Only admin can call",
    request_body = GrantAccessBody,
    responses(
        (status = OK, description = "Success", body = GrantAccessResponse, content_type = "application/json")
    ),
    security(("docker_basic" = []))
)]
pub async fn grant_access(
    State(state): State<AppState>,
    PermissionExtractor { user, .. }: PermissionExtractor,
    Json(body): Json<GrantAccessBody>,
) -> crate::Result<Json<GrantAccessResponse>> {
    verify_admin(&user)?;

    let user = User::find_by_name(&body.name, state.db()).await?;
    user.add_permission(body.image, body.access, state.db()).await?;


    Ok(Json(GrantAccessResponse { user_name: user.name }))
}