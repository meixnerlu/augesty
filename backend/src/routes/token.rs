use axum::{Json, extract::State};
use axum_extra::extract::{Query, WithRejection};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    TOKEN_TAG,
    error::LoggedRejection,
    extractors::{GithubExtractor, PermissionExtractor},
    models::{permission::PermissionType, user::User},
    state::AppState,
};

#[derive(Debug, Clone, IntoParams, Deserialize)]
pub struct TokenQuery {
    pub service: String,
    #[serde(default)]
    pub scope: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Scope {
    #[serde(rename(serialize = "type"))]
    pub kind: String,
    pub name: String,
    pub actions: Vec<PermissionType>,
}

impl Scope {
    pub fn parse_str(input: &str) -> crate::Result<Self> {
        let mut parts = input.splitn(3, ':');
        let kind = parts.next().ok_or("missing kind")?;
        let name = parts.next().ok_or("missing name")?;
        let actions_raw = parts.next().ok_or("missing actions")?;

        if kind.is_empty() || name.is_empty() || actions_raw.is_empty() {
            return Err("kind, name, and actions must be non-empty".into());
        }

        let mut actions = Vec::new();
        for action_str in actions_raw.split(',') {
            let a = action_str.trim();
            if a.is_empty() {
                continue;
            }
            actions.push(PermissionType::from_actions(a)?);
        }

        if actions.is_empty() {
            return Err("no valid actions found".into());
        }

        Ok(Self {
            kind: kind.to_string(),
            name: name.to_string(),
            actions,
        })
    }
}

#[derive(Debug, Clone, ToSchema, Serialize)]
pub struct TokenResponse {
    token: String,
    expires_in: u64, // in seconds
}

#[utoipa::path(
    method(get),
    tag = TOKEN_TAG,
    path = "/api/token",
    description = "The token endpoint for docker to fetch a registry token",
    params(TokenQuery),
    responses(
        (status = OK, description = "Success", body = TokenResponse, content_type = "application/json")
    ),
    security(("docker_basic" = []))
)]
pub async fn token(
    State(state): State<AppState>,
    PermissionExtractor { user, permissions }: PermissionExtractor,
    WithRejection(Query(params), _): WithRejection<Query<TokenQuery>, LoggedRejection>,
) -> crate::Result<Json<TokenResponse>> {
    let scopes: Vec<Scope> = params
        .scope
        .into_iter()
        .map(|scope| Scope::parse_str(&scope))
        .collect::<Result<_, _>>()?;

    tracing::debug!("{:<12}- Scopes: {scopes:?}", "REQUEST");
    tracing::debug!("{:<12}- Perms: {permissions:?}", "REQUEST");
    for scope in &scopes {
        let permission_types: Vec<PermissionType> = permissions
            .iter()
            .filter(|perm| {
                scope.kind == "repository" && (scope.name == perm.subject || perm.subject == "*")
            })
            .map(|perm| perm.permission.clone())
            .collect();
        if !scope
            .actions
            .iter()
            .all(|action| permission_types.contains(action))
        {
            return Err(crate::Error::Unauthorized("Insufficient Permissions"));
        }
    }

    if &params.service != state.docker_url() {
        tracing::debug!(
            "{:<12}- registry {} asked for registry {}",
            "Error",
            &params.service,
            state.docker_url()
        );
        return Err(crate::Error::Unauthorized("Invalid Registry"));
    }

    let (token, expires_in) = state.create_docker_jwt(&user.name, &params.service, scopes)?;

    Ok(Json(TokenResponse { token, expires_in }))
}

#[derive(Debug, Clone, ToSchema, Deserialize)]
pub struct IdentifyBody {
    service_account: String,
}

#[derive(Debug, Clone, ToSchema, Serialize)]
pub struct IdentifyResponse {
    accesstoken: String,
}

#[utoipa::path(
    method(post),
    tag = TOKEN_TAG,
    path = "/api/identify",
    description = "The endpoint for the action to request a service account jwt",
    request_body = IdentifyBody,
    responses(
        (status = OK, description = "Success", body = IdentifyResponse, content_type = "application/json")
    ),
    security(("service_bearer" = []))
)]
pub async fn identify(
    State(state): State<AppState>,
    GithubExtractor(repo): GithubExtractor,
    Json(body): Json<IdentifyBody>,
) -> crate::Result<Json<IdentifyResponse>> {
    let svc_account = User::find_by_name(&body.service_account, state.db()).await?;
    let idents = svc_account.get_identifiers(state.db()).await?;

    if !idents.iter().any(|ident| *ident == *repo) {
        return Err(crate::Error::Unauthorized(
            "This repo cant access this service account",
        ));
    }

    let accesstoken = state.create_jwt(svc_account.name)?;

    Ok(Json(IdentifyResponse { accesstoken }))
}
