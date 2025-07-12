use sqlx::prelude::FromRow;

use crate::models::user::User;

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct UserPasswordHash {
    pub user_id: i64,
    pub pw_hash: String,
}

impl UserPasswordHash {
    pub async fn find_pw(name: &str, pool: &sqlx::SqlitePool) -> crate::Result<Self> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, name, user_type FROM users WHERE name = ?",
            name
        )
        .fetch_one(pool)
        .await?;
        let user_id = user.id.ok_or(crate::Error::Opaque("User ID must exist"))?;

        sqlx::query_as!(
            Self,
            "SELECT user_id, pw_hash FROM user_pw_hash WHERE user_id = ?",
            user_id
        )
        .fetch_optional(pool)
        .await?
        .ok_or(crate::Error::BadRequest("User is serviceaccount"))
    }
}
