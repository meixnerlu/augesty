use std::fmt::Display;

use sqlx::prelude::{FromRow, Type};

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Permission {
    pub id: Option<i64>,
    pub subject: String,
    pub permission: PermissionType,
}

#[derive(Debug, Clone, PartialEq, Eq, Type, serde::Serialize, serde::Deserialize)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum PermissionType {
    Pull,
    Push,
}

impl PermissionType {
    pub fn from_actions(s: &str) -> crate::Result<Self> {
        match s {
            "pull" => Ok(PermissionType::Pull),
            "push" => Ok(PermissionType::Push),
            _ => Err(crate::Error::BadRequest("Unknown action")),
        }
    }
}

impl From<String> for PermissionType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "pull" => Self::Pull,
            "push" => Self::Push,
            other => panic!("Unknown permission type {other}"), // should not happen bc of schema constraints
        }
    }
}

impl Display for PermissionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            &Self::Pull => "pull",
            &Self::Push => "push",
        };
        write!(f, "{}", text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct UserPermission {
    pub user_id: i64,
    pub permission_id: i64,
}
