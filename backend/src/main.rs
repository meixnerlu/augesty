use axum::Router;
pub use error::{Error, Result};
use serde::Serialize;
use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpBuilder, SecurityScheme},
};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_swagger_ui::SwaggerUi;

use crate::{models::user::User, state::AppState};

mod error;
mod extractors;
mod models;
mod routes;
mod state;

const PORT: u16 = 8080;

const USER_TAG: &str = "user";
const TOKEN_TAG: &str = "token";

#[derive(Debug, Serialize)]
struct Modifier;

impl Modify for Modifier {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(schema) = openapi.components.as_mut() {
            schema.add_security_scheme(
                "service_bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
            schema.add_security_scheme(
                "docker_basic",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Basic)
                        .bearer_format("name:JWT")
                        .build(),
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    tags(
        (name = USER_TAG, description = "User API endpoints"),
        (name = TOKEN_TAG, description = "Token API endpoints")
    ),
    modifiers(&Modifier),
    security(
        ("service_bearer" = [], "docker_basic" = [])
    )
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    trace::init_tracing();

    let state = match state::AppState::new().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("{:<12}- Failed to initialize state: {}", "State", e);
            std::process::exit(1);
        }
    };

    sqlx::migrate!("./migrations").run(state.db()).await?;
    if let Err(e) = User::generate_admin(state.db()).await {
        tracing::error!("{:<12}- Failed to initialize admin account: {}", "Admin", e);
        std::process::exit(1);
    }

    let (router, api): (axum::Router<AppState>, utoipa::openapi::OpenApi) =
        OpenApiRouter::with_openapi(ApiDoc::openapi())
            .routes(routes!(routes::token::token, routes::token::identify))
            .routes(routes!(routes::user::grant_access))
            .routes(routes!(routes::user::create_user))
            .routes(routes!(routes::user::create_service_account))
            .routes(routes!(routes::user::add_identifier))
            .with_state(state.clone())
            .split_for_parts();

    let router: Router<_> = router
        .layer(axum::middleware::from_fn(trace::logging_layer))
        .with_state(state.clone())
        .merge(SwaggerUi::new("/api/swagger").url("/api/openapi.json", api));

    let app = router.into_make_service();
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{PORT}"))
        .await
        .unwrap();

    tracing::info!("{:<12}- Server running on http://0.0.0.0:{PORT}", "API");

    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    
    tokio::fs::remove_file("/config/jwt.pub").await?;
    state.db().close().await;
    tracing::info!("{:<12}- Server shut down gracefully", "API");

    Ok(())
}

mod trace {
    use axum::{extract::Request, middleware::Next, response::Response};
    use tokio::time::Instant;
    use tracing::info;
    use tracing_subscriber::EnvFilter;

    pub async fn logging_layer(request: Request, next: Next) -> Response {
        let method = request.method().to_string();
        let route = request.uri().path().to_string();
        let uuid = uuid::Uuid::new_v4();
        info!(
            "{:<12} - Handling {method} on {route} with id {uuid}",
            "REQUEST"
        );

        let now = Instant::now();
        let response = next.run(request).await;
        let elapsed = now.elapsed().as_millis();

        let status = response.status().to_string();
        info!(
            "{:<12} - {uuid} returned {status} in {elapsed} ms",
            "RESPONSE"
        );

        response
    }

    pub fn init_tracing() {
        let sub = tracing_subscriber::fmt()
            .with_target(false)
            .with_env_filter(EnvFilter::from_default_env());

        if cfg!(debug_assertions) {
            sub.without_time()
                .with_file(false)
                .with_line_number(false)
                .init();
        } else {
            sub.json().init();
        }
    }
}

async fn shutdown_signal() {
    let ctrl = async {
        tokio::signal::ctrl_c().await.expect("error listening for ctrl_c");
    };
    #[cfg(unix)]
    let term = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("error listening for SIGTERM")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl => {},
        _ = term => {},
    }
}