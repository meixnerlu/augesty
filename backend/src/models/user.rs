use sqlx::{
    Sqlite, Transaction,
    prelude::{FromRow, Type},
};

use crate::models::{permission::Permission, user_identifier::UserIdentifier};

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct User {
    pub id: Option<i64>,
    pub name: String,
    pub user_type: UserType,
}

#[derive(Debug, Clone, PartialEq, Eq, Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum UserType {
    User,
    ServiceAccount,
}

impl From<String> for UserType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "user" => Self::User,
            "serviceaccount" => Self::ServiceAccount,
            _ => panic!("Unknown user type"),
        }
    }
}

impl User {
    pub fn new_user(name: String) -> Self {
        Self {
            id: None,
            name,
            user_type: UserType::User,
        }
    }

    pub async fn add_hash(&self, pw_hash: &str, pool: &sqlx::SqlitePool) -> crate::Result<()> {
        if self.user_type != UserType::User {
            return Err(crate::Error::BadRequest(
                "Cannot add password hash to service account",
            ));
        }
        sqlx::query!(
            "INSERT INTO user_pw_hash (user_id, pw_hash) VALUES (?, ?)",
            self.id,
            pw_hash
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    pub fn new_service_account(name: String) -> Self {
        Self {
            id: None,
            name,
            user_type: UserType::ServiceAccount,
        }
    }

    pub async fn find_by_name(name: &str, pool: &sqlx::SqlitePool) -> crate::Result<User> {
        let user = sqlx::query_as!(User, "SELECT * FROM users WHERE name = ?", name)
            .fetch_one(pool)
            .await?;

        Ok(user)
    }

    pub async fn add_user_identifier(
        &self,
        identifier: &str,
        pool: &sqlx::SqlitePool,
    ) -> crate::Result<()> {
        if self.user_type != UserType::ServiceAccount {
            return Err(crate::Error::BadRequest("Cannot add identifier to user"));
        }

        sqlx::query!(
            "INSERT INTO user_identifiers (user_id, identifier) VALUES (?, ?)",
            self.id,
            identifier
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn get_identifiers(&self, pool: &sqlx::SqlitePool) -> crate::Result<Vec<String>> {
        if self.user_type != UserType::ServiceAccount {
            return Err(crate::Error::BadRequest("User is not ServiceAccount"));
        }

        let identifiers = sqlx::query_as!(
            UserIdentifier,
            "SELECT * FROM user_identifiers WHERE user_id = ?",
            self.id
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|ident| ident.identifier)
        .collect();

        Ok(identifiers)
    }

    pub async fn insert(&self, pool: &sqlx::SqlitePool) -> crate::Result<()> {
        sqlx::query!(
            "INSERT INTO users (id, name, user_type) VALUES (?, ?, ?)",
            self.id,
            self.name,
            self.user_type
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn add_permission(
        &self,
        subject: String,
        permission_type: String,
        pool: &sqlx::SqlitePool,
    ) -> crate::Result<()> {
        let user_id = match self.id {
            Some(id) => id,
            None => return Err(crate::Error::Opaque("Missing user_id")), // should not happen
        };

        let mut tx: Transaction<'_, Sqlite> = pool.begin().await?;
        let perm_str = permission_type.to_string();
        sqlx::query!(
            r#"
            INSERT OR IGNORE INTO permissions (subject, permission)
            VALUES (?, ?)
            "#,
            subject,
            perm_str,
        )
        .execute(&mut *tx)
        .await?;

        let permission = sqlx::query_as!(
            Permission,
            r#"
            SELECT * FROM permissions
            WHERE subject = ? AND permission = ?
            "#,
            subject,
            perm_str,
        )
        .fetch_one(&mut *tx)
        .await?;

        let permission_id = match permission.id {
            Some(id) => id,
            None => return Err(crate::Error::Opaque("Missing permission_id")), // should not happen
        };

        sqlx::query!(
            r#"
            INSERT OR IGNORE INTO user_permissions (user_id, permission_id)
            VALUES (?, ?)
            "#,
            user_id,
            permission_id,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }

    pub async fn list(pool: &sqlx::SqlitePool) -> crate::Result<Vec<Self>> {
        let users = sqlx::query_as!(Self, "SELECT id, name, user_type FROM users")
            .fetch_all(pool)
            .await?;
        Ok(users)
    }

    pub async fn list_permissions(
        &self,
        pool: &sqlx::SqlitePool,
    ) -> crate::Result<Vec<crate::models::permission::Permission>> {
        let permissions = sqlx::query_as!(
            crate::models::permission::Permission,
            r"
            SELECT p.id, p.subject, p.permission
            FROM users u
            JOIN user_permissions up ON u.id = up.user_id
            JOIN permissions p ON up.permission_id = p.id
            WHERE u.name = ?;
            ",
            self.name
        )
        .fetch_all(pool)
        .await?;
        Ok(permissions)
    }

    pub async fn delete_by_id(id: i64, pool: &sqlx::SqlitePool) -> crate::Result<()> {
        sqlx::query!("DELETE FROM users WHERE id = ?", id)
            .execute(pool)
            .await?;
        Ok(())
    }
}

// for init
impl User {
    pub async fn generate_admin(pool: &sqlx::SqlitePool) -> crate::Result<()> {
        use argon2::PasswordHasher;

        let user = Self::new_user("admin".to_string());
        sqlx::query!(
            r"
            INSERT OR IGNORE INTO users (name, user_type) 
            VALUES (?, 'user');
            ",
            user.name
        )
        .execute(pool)
        .await?;

        let pw_exists = sqlx::query!("SELECT user_id FROM user_pw_hash WHERE user_id = (SELECT id FROM users WHERE name = 'admin')").fetch_optional(pool).await?.is_some();

        if !pw_exists {
            let salt = argon2::password_hash::SaltString::generate(
                &mut argon2::password_hash::rand_core::OsRng,
            );
            let argon = argon2::Argon2::default();

            let pw = Self::generate_password(32);
            tracing::info!("{:<12}- Admin password is {pw}! KEEP IT SAFE!", "Password");
            let pw_hash = argon.hash_password(pw.as_bytes(), &salt)?.to_string();

            user.add_hash(&pw_hash, pool).await?;
        }

        sqlx::query!(
            r"
            INSERT OR IGNORE INTO permissions(subject, permission)
            VALUES 
                ('*', 'pull'),
                ('*', 'push');

            INSERT OR IGNORE INTO user_permissions(user_id, permission_id)
            SELECT u.id, p.id
            FROM users AS u
            JOIN permissions AS p 
                ON p.subject = '*' 
                AND p.permission = 'pull'
            WHERE u.name = 'admin';

            INSERT OR IGNORE INTO user_permissions(user_id, permission_id)
            SELECT u.id, p.id
            FROM users AS u
            JOIN permissions AS p 
                ON p.subject = '*' 
                AND p.permission = 'push'
            WHERE u.name = 'admin';
            "
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    fn generate_password(len: usize) -> String {
        use rand::Rng;

        rand::rng()
            .sample_iter(&rand::distr::Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }
}
