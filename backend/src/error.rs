use axum::response::{IntoResponse, Response};
use derive_more::{Display, From};

#[derive(Debug, From, Display)]
pub enum Error {
    BadRequest(&'static str),
    Unauthorized(&'static str),
    NotFound(&'static str),
    #[from]
    Io(tokio::io::Error),
    #[from]
    Api(axum::Error),
    #[from]
    Migration(sqlx::migrate::MigrateError),
    #[from]
    Db(sqlx::Error),
    #[from]
    MissingEnvVar(std::env::VarError),
    #[from]
    Hash(argon2::password_hash::Error),
    #[from]
    Argon(argon2::Error),
    #[from]
    Opaque(&'static str),
    #[from]
    Jwt(jwt_simple::Error),
    #[from]
    Ssl(openssl::error::ErrorStack),
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        tracing::error!("{:<12}- Error occurred: {}", "Request", self);
        let status = match self {
            Error::BadRequest(_) => axum::http::StatusCode::BAD_REQUEST,
            Error::Unauthorized(_) => axum::http::StatusCode::UNAUTHORIZED,
            Error::NotFound(_) => axum::http::StatusCode::NOT_FOUND,
            _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = self.to_string();
        Response::builder()
            .status(status)
            .body(body.into())
            .unwrap()
    }
}
