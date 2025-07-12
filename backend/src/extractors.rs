use std::ops::Deref;

use axum::{
    RequestPartsExt,
    extract::{FromRef, FromRequestParts, State},
};
use axum_extra::{
    TypedHeader,
    headers::{
        Authorization,
        authorization::{Basic, Bearer},
    },
};
use github_oidc::GitHubOIDCConfig;

use crate::{
    models::{permission::Permission, user::User},
    state::AppState,
};

pub struct PermissionExtractor {
    pub user: User,
    pub permissions: Vec<Permission>,
}

impl<S> FromRequestParts<S> for PermissionExtractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = crate::Error;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let State(state): State<AppState> = State::from_request_parts(parts, state)
            .await
            .map_err(|_| crate::Error::Opaque("Internal Server Error"))?;

        let basic = parts
            .extract::<TypedHeader<Authorization<Basic>>>()
            .await
            .map_err(|_| crate::Error::Unauthorized("Not Basic Auth"))?
            .0;
        let user = User::find_by_name(basic.username(), state.db())
            .await
            .map_err(|_| crate::Error::Unauthorized("User does not exist"))?;
        let permissions = state
            .get_permissions(user.clone(), basic.password())
            .await?;

        Ok(PermissionExtractor { user, permissions })
    }
}

const GITHUB_OIDC_URL: &str = "https://token.actions.githubusercontent.com";

pub struct GithubExtractor(pub GithubRepo);

pub struct GithubRepo(String);

impl Deref for GithubRepo {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for GithubExtractor
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = crate::Error;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let oidc_token = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| crate::Error::Unauthorized("Not Bearer Auth"))?
            .0
            .token()
            .to_string();
        let jwks = github_oidc::fetch_jwks(GITHUB_OIDC_URL)
            .await
            .map_err(|_| crate::Error::Opaque("Error fetching github jwks"))?;
        let claims = jwks
            .validate_github_token(
                &oidc_token,
                &GitHubOIDCConfig {
                    ..Default::default()
                },
            )
            .map_err(|_| crate::Error::Unauthorized("Invalid OIDC Token"))?;

        Ok(GithubExtractor(GithubRepo(claims.repository)))
    }
}
