use sqlx::prelude::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct UserIdentifier {
    pub id: Option<i64>,
    pub user_id: i64,
    pub identifier: String,
}
