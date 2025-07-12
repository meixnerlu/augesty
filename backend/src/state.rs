use argon2::PasswordVerifier;
use jwt_simple::prelude::{ECDSAP384KeyPairLike, ECDSAP384PublicKeyLike, ES384KeyPair};
use openssl::{
    asn1::Asn1Time,
    ec::EcKey,
    pkey::PKey,
    x509::{X509Builder, X509NameBuilder},
};
use std::{ops::Deref, sync::Arc};

use crate::{
    models::{permission::Permission, user::User, user_pw_hash::UserPasswordHash},
    routes::token::Scope,
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<InnerState>,
}

impl AppState {
    pub async fn new() -> crate::Result<Self> {
        let inner = InnerState::new().await?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

impl Deref for AppState {
    type Target = InnerState;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct InnerState {
    db: sqlx::SqlitePool,
    jwt_key: ES384KeyPair,
    own_url: String,
    docker_url: String,
}

impl InnerState {
    pub async fn new() -> crate::Result<Self> {
        let db_url = std::env::var("DATABASE_PATH")?;
        let mut db_options = sqlx::sqlite::SqliteConnectOptions::new();
        db_options = db_options.create_if_missing(true);
        db_options = db_options.filename(&db_url);
        let db = sqlx::SqlitePool::connect_with(db_options).await?;
        let jwt_key = ES384KeyPair::generate();
        let own_url = std::env::var("OWN_URL")?;
        let docker_url = std::env::var("DOCKER_URL")?;
        let cert = create_cert_from_pair(&jwt_key, &own_url)?;
        tokio::fs::write("/config/jwt.pub", cert).await?;

        Ok(InnerState {
            db,
            jwt_key,
            own_url,
            docker_url,
        })
    }

    pub fn db(&self) -> &sqlx::SqlitePool {
        &self.db
    }

    pub fn docker_url(&self) -> &String {
        &self.docker_url
    }

    // Returns a JWT key as a String for a svc account
    pub fn create_jwt(&self, name: String) -> crate::Result<String> {
        let claims = SvcClaims { svc_name: name };
        let claims = jwt_simple::claims::Claims::with_custom_claims(
            claims,
            jwt_simple::prelude::Duration::from_mins(5),
        );
        self.jwt_key
            .sign(claims)
            .map_err(|_| crate::Error::Opaque("Failed to create JWT token"))
    }

    pub fn create_docker_jwt(
        &self,
        sub: &str,
        aud: &str,
        scope: Vec<Scope>,
    ) -> crate::Result<(String, i32)> {
        let expires_in = 300; // seconds in 5 minutes

        let claims = DockerClaims { access: scope };
        let mut claims = jwt_simple::claims::Claims::with_custom_claims(
            claims,
            jwt_simple::prelude::Duration::from_mins(5),
        );
        claims = claims.with_audience(aud);
        claims = claims.with_subject(sub);
        claims = claims.with_issuer(&self.own_url);

        let jwt = self
            .jwt_key
            .sign(claims)
            .map_err(|_| crate::Error::Opaque("Failed to create JWT token"))?;

        Ok((jwt, expires_in))
    }

    fn verify_jwt(&self, token: &str) -> crate::Result<SvcClaims> {
        let custom_claims = self
            .jwt_key
            .public_key()
            .verify_token::<SvcClaims>(token, None)
            .map_err(|_| crate::Error::Unauthorized("Invalid JWT token"))?
            .custom;

        Ok(custom_claims)
    }

    async fn permissions_for_svc_account(
        &self,
        user: User,
        token: &str,
    ) -> crate::Result<Vec<Permission>> {
        let claims = self.verify_jwt(token)?;
        if user.name != claims.svc_name {
            return Err(crate::Error::Unauthorized("Missmatched user and token"));
        }
        let permissions = user.list_permissions(self.db()).await?;
        Ok(permissions)
    }

    async fn permissions_for_user(&self, user: User, pass: &str) -> crate::Result<Vec<Permission>> {
        let pw_hash = UserPasswordHash::find_pw(&user.name, self.db()).await?;
        let hash = argon2::PasswordHash::try_from(pw_hash.pw_hash.as_str())?;
        let phfs = argon2::Argon2::default();
        phfs.verify_password(pass.as_bytes(), &hash)
            .map_err(|_| crate::Error::Unauthorized("Invalid password"))?;

        user.list_permissions(self.db()).await
    }

    pub async fn get_permissions(&self, user: User, pass: &str) -> crate::Result<Vec<Permission>> {
        let perms = match user.user_type {
            crate::models::user::UserType::ServiceAccount => {
                self.permissions_for_svc_account(user, pass).await?
            }
            crate::models::user::UserType::User => self.permissions_for_user(user, pass).await?,
        };

        Ok(perms)
    }
}

fn create_cert_from_pair(pair: &ES384KeyPair, own_url: &str) -> crate::Result<Vec<u8>> {
    let private_pem = pair.to_pem()?;
    let ec_key = EcKey::private_key_from_pem(&private_pem.as_bytes())?;
    let pkey = PKey::from_ec_key(ec_key)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", own_url)?;
    let name = name.build();

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    builder.set_not_before(&Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(&Asn1Time::days_from_now(365)?.as_ref())?;
    let mut serial = openssl::bn::BigNum::new()?;
    serial.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;

    builder.set_serial_number(&serial.as_ref())?;
    builder.sign(&pkey, openssl::hash::MessageDigest::sha384())?;

    Ok(builder.build().to_pem()?)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SvcClaims {
    pub svc_name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DockerClaims {
    pub access: Vec<Scope>,
}

#[tokio::test]
async fn test_docker_jwt() -> crate::Result<()> {
    _ = dotenvy::dotenv();
    crate::trace::init_tracing();

    let state = AppState::new().await?;
    let scope = Scope {
        kind: "repository".to_string(),
        name: "example/image".to_string(),
        actions: vec![crate::models::permission::PermissionType::Push],
    };
    let (jwt, expires_in) =
        state.create_docker_jwt("admin", "registry.example.com", vec![scope])?;

    tracing::info!("The jwt\n\n{jwt}\n\nexpires in {expires_in} seconds");

    Ok(())
}
