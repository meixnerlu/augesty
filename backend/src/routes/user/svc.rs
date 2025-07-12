use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{extractors::PermissionExtractor, models::user::User, state::AppState, USER_TAG};

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct CreateServiceAccountBody {
    name: String,
}

#[derive(Debug, Clone, ToSchema, Serialize)]
pub struct CreateServiceAccountResponse {
    svc_name: String
}

#[utoipa::path(
    method(post),
    tag = USER_TAG,
    path = "/api/service_account",
    description = "Only admin can call",
    request_body = CreateServiceAccountBody,
    responses(
        (status = OK, description = "Success", body = CreateServiceAccountResponse, content_type = "application/json")
    ),
    security(("docker_basic" = []))
)]
pub async fn create_service_account(
    State(state): State<AppState>,
    PermissionExtractor { user, .. }: PermissionExtractor,
    Json(body): Json<CreateServiceAccountBody>,
) -> crate::Result<Json<CreateServiceAccountResponse>> {
    super::verify_admin(&user)?;

    let user = User::new_service_account(body.name);
    user.insert(state.db()).await?;

    Ok(Json(CreateServiceAccountResponse { svc_name: user.name }))
}

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct AddIdentifierBody {
    svc_name: String,
    repo: String
}

#[derive(Debug, Clone, ToSchema, Serialize)]
pub struct AddIdentifierResponse {
    svc_name: String
}

#[utoipa::path(
    method(post),
    tag = USER_TAG,
    path = "/api/service_account/identifier",
    description = "Only admin can call",
    request_body = AddIdentifierBody,
    responses(
        (status = OK, description = "Success", body = AddIdentifierResponse, content_type = "application/json")
    ),
    security(("docker_basic" = []))
)]
pub async fn add_identifier(
    State(state): State<AppState>,
    PermissionExtractor { user, .. }: PermissionExtractor,
    Json(body): Json<AddIdentifierBody>,
) -> crate::Result<Json<AddIdentifierResponse>> {
    super::verify_admin(&user)?;

    let user = User::find_by_name(&body.svc_name, state.db()).await?;
    user.add_user_identifier(&body.repo, state.db()).await?;

    Ok(Json(AddIdentifierResponse { svc_name: user.name }))
}