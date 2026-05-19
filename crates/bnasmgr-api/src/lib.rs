use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use bnasmgr_helper::{
    allowed_service, valid_quota, HelperClient, HelperOperation, HelperRequest, ServiceAction,
};
use chrono::{DateTime, Utc};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Column, Row, SqlitePool};
use std::{collections::BTreeMap, sync::Arc};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    db: SqlitePool,
    helper: Arc<dyn HelperClient>,
}

impl AppState {
    pub fn new(db: SqlitePool, helper: Arc<dyn HelperClient>) -> Self {
        Self { db, helper }
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        for sql in [
            "create table if not exists dashboard_users (
                id text primary key,
                username text not null unique,
                password_hash text not null,
                is_admin integer not null,
                must_change_password integer not null,
                created_at text not null
            )",
            "create table if not exists sessions (
                token text primary key,
                user_id text not null,
                created_at text not null,
                expires_at text not null
            )",
            "create table if not exists shares_samba (
                id text primary key,
                name text not null unique,
                path text not null,
                allowed_users text not null,
                readonly integer not null,
                created_at text not null
            )",
            "create table if not exists samba_users (
                username text primary key,
                enabled integer not null,
                created_at text not null,
                updated_at text not null
            )",
            "create table if not exists shares_nfs (
                id text primary key,
                path text not null,
                clients text not null,
                options text not null,
                created_at text not null
            )",
            "create table if not exists audit_events (
                id text primary key,
                actor text not null,
                category text not null,
                target text not null,
                result text not null,
                message text not null,
                created_at text not null
            )",
            "create table if not exists helper_history (
                id text primary key,
                actor text not null,
                operation text not null,
                ok integer not null,
                message text not null,
                created_at text not null
            )",
            "create table if not exists app_settings (
                key text primary key,
                value text not null
            )",
        ] {
            sqlx::query(sql).execute(&self.db).await?;
        }
        Ok(())
    }

    pub async fn seed_admin(&self) -> anyhow::Result<()> {
        let count: i64 =
            sqlx::query_scalar("select count(*) from dashboard_users where username = 'admin'")
                .fetch_one(&self.db)
                .await?;
        if count == 0 {
            sqlx::query("insert into dashboard_users (id, username, password_hash, is_admin, must_change_password, created_at) values (?, ?, ?, 1, 1, ?)")
                .bind(Uuid::new_v4().to_string())
                .bind("admin")
                .bind(hash_password("admin")?)
                .bind(Utc::now().to_rfc3339())
                .execute(&self.db)
                .await?;
        }
        Ok(())
    }

    async fn helper(
        &self,
        actor: &str,
        operation: HelperOperation,
    ) -> Result<serde_json::Value, ApiError> {
        let operation_json = redacted_operation_json(&operation);
        let response = self
            .helper
            .execute(HelperRequest {
                actor: actor.into(),
                operation,
            })
            .await
            .map_err(|err| ApiError::bad_request(err.to_string()))?;
        sqlx::query("insert into helper_history (id, actor, operation, ok, message, created_at) values (?, ?, ?, ?, ?, ?)")
            .bind(Uuid::new_v4().to_string())
            .bind(actor)
            .bind(operation_json)
            .bind(if response.ok { 1 } else { 0 })
            .bind(&response.message)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.db)
            .await?;
        self.audit(
            actor,
            &response.category,
            &response.target,
            if response.ok { "ok" } else { "error" },
            &response.message,
        )
        .await?;
        if response.ok {
            Ok(response.data)
        } else {
            Err(ApiError::bad_request(response.message))
        }
    }

    async fn audit(
        &self,
        actor: &str,
        category: &str,
        target: &str,
        result: &str,
        message: &str,
    ) -> Result<(), ApiError> {
        sqlx::query("insert into audit_events (id, actor, category, target, result, message, created_at) values (?, ?, ?, ?, ?, ?, ?)")
            .bind(Uuid::new_v4().to_string())
            .bind(actor)
            .bind(category)
            .bind(target)
            .bind(result)
            .bind(message)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.db)
            .await?;
        Ok(())
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(login))
        .route("/api/auth/change-password", post(change_password))
        .route("/api/auth/me", get(me))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/:id", delete(delete_user))
        .route("/api/users/:id/role", post(update_user_role))
        .route("/api/users/:id/reset-password", post(reset_user_password))
        .route("/api/storage/overview", get(storage_overview))
        .route("/api/storage/quota", post(set_quota))
        .route("/api/snapshots", get(list_snapshots).post(create_snapshot))
        .route("/api/snapshots/:snapshot", delete(delete_snapshot))
        .route("/api/snapshots/:snapshot/rollback", post(rollback_snapshot))
        .route("/api/shares/samba", get(list_samba).post(upsert_samba))
        .route(
            "/api/shares/samba/users",
            get(list_samba_users).post(upsert_samba_user),
        )
        .route(
            "/api/shares/samba/users/:username",
            delete(delete_samba_user),
        )
        .route("/api/shares/samba/:id", delete(delete_samba))
        .route("/api/shares/nfs", get(list_nfs).post(upsert_nfs))
        .route("/api/shares/nfs/:id", delete(delete_nfs))
        .route("/api/services", get(list_services))
        .route("/api/services/:service/:action", post(service_action))
        .route("/api/logs", get(logs))
        .route("/api/audit", get(audit))
        .route("/api/audit/helper-history", get(helper_history))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }
    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(value: sqlx::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: value.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

#[derive(Debug, Clone, Serialize)]
struct AuthUser {
    id: String,
    username: String,
    is_admin: bool,
    must_change_password: bool,
}

async fn auth(headers: &HeaderMap, state: &AppState) -> Result<AuthUser, ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    let row = sqlx::query(
        "select u.id, u.username, u.is_admin, u.must_change_password
         from sessions s join dashboard_users u on u.id = s.user_id
         where s.token = ? and s.expires_at > ?",
    )
    .bind(token)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(&state.db)
    .await?;
    let row = row.ok_or_else(|| ApiError::unauthorized("invalid session"))?;
    Ok(AuthUser {
        id: row.get("id"),
        username: row.get("username"),
        is_admin: row.get::<i64, _>("is_admin") == 1,
        must_change_password: row.get::<i64, _>("must_change_password") == 1,
    })
}

fn require_admin(user: &AuthUser) -> Result<(), ApiError> {
    if !user.is_admin {
        return Err(ApiError::forbidden("admin role required"));
    }
    Ok(())
}

fn require_privileged(user: &AuthUser) -> Result<(), ApiError> {
    require_admin(user)?;
    if user.must_change_password {
        return Err(ApiError::forbidden(
            "password change required before privileged actions",
        ));
    }
    Ok(())
}

fn legacy_hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"bnasmgr:");
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?
        .to_string())
}

fn verify_password(stored_hash: &str, password: &str) -> bool {
    if stored_hash.starts_with("$argon2") {
        return PasswordHash::new(stored_hash)
            .ok()
            .and_then(|parsed| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .ok()
            })
            .is_some();
    }
    stored_hash == legacy_hash_password(password)
}

fn is_legacy_password_hash(stored_hash: &str) -> bool {
    !stored_hash.starts_with("$argon2")
}

fn reject_shell_chars(value: &str, field: &str) -> Result<(), ApiError> {
    if value.trim().is_empty()
        || value.contains('\0')
        || value.contains('\n')
        || value.contains(';')
        || value.contains('&')
        || value.contains('|')
        || value.contains('`')
    {
        return Err(ApiError::bad_request(format!(
            "{field} contains unsafe characters"
        )));
    }
    Ok(())
}

fn validate_share_name(name: &str) -> Result<(), ApiError> {
    reject_shell_chars(name, "share name")?;
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(ApiError::bad_request(
            "share name may only contain letters, numbers, dots, dashes, and underscores",
        ));
    }
    Ok(())
}

fn validate_absolute_path(path: &str) -> Result<(), ApiError> {
    reject_shell_chars(path, "path")?;
    if !path.starts_with('/') || path.contains("/../") || path.ends_with("/..") {
        return Err(ApiError::bad_request(
            "path must be absolute and must not contain parent traversal",
        ));
    }
    Ok(())
}

fn validate_dataset_name(dataset: &str) -> Result<(), ApiError> {
    reject_shell_chars(dataset, "dataset")?;
    if dataset.starts_with('/') || dataset.contains("..") || dataset.contains('@') {
        return Err(ApiError::bad_request("dataset name is not valid"));
    }
    Ok(())
}

fn validate_snapshot_name(snapshot: &str) -> Result<(), ApiError> {
    reject_shell_chars(snapshot, "snapshot")?;
    let Some((dataset, name)) = snapshot.split_once('@') else {
        return Err(ApiError::bad_request(
            "snapshot must include dataset@snapshot",
        ));
    };
    validate_dataset_name(dataset)?;
    if name.trim().is_empty() || name.contains('/') || name.contains("..") {
        return Err(ApiError::bad_request("snapshot name is not valid"));
    }
    Ok(())
}

fn validate_snapshot_label(name: &str) -> Result<(), ApiError> {
    reject_shell_chars(name, "snapshot name")?;
    if name.contains('/') || name.contains('@') || name.contains("..") {
        return Err(ApiError::bad_request("snapshot name is not valid"));
    }
    Ok(())
}

fn require_snapshot_confirmation(headers: &HeaderMap, snapshot: &str) -> Result<(), ApiError> {
    let confirmed = headers
        .get("x-bnasmgr-confirm")
        .and_then(|value| value.to_str().ok());
    if confirmed != Some(snapshot) {
        return Err(ApiError::bad_request(
            "destructive snapshot operation requires x-bnasmgr-confirm header matching the snapshot name",
        ));
    }
    Ok(())
}

fn validate_quota_value(quota: &str) -> Result<(), ApiError> {
    reject_shell_chars(quota, "quota")?;
    if !valid_quota(quota) {
        return Err(ApiError::bad_request(
            "quota must be none/off or a numeric value with optional K, M, G, T, P, or E suffix",
        ));
    }
    Ok(())
}

fn validate_user_list(users: &[String]) -> Result<(), ApiError> {
    for username in users {
        reject_shell_chars(username, "allowed user")?;
        if !username
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        {
            return Err(ApiError::bad_request(
                "allowed users may only contain letters, numbers, dots, dashes, and underscores",
            ));
        }
    }
    Ok(())
}

fn validate_storage_username(username: &str) -> Result<(), ApiError> {
    reject_shell_chars(username, "username")?;
    if !username
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(ApiError::bad_request(
            "username may only contain letters, numbers, dots, dashes, and underscores",
        ));
    }
    Ok(())
}

fn redacted_operation_json(operation: &HelperOperation) -> String {
    let value = match operation {
        HelperOperation::UpsertSambaUser {
            username, enabled, ..
        } => serde_json::json!({
            "upsert_samba_user": {
                "username": username,
                "password": "<redacted>",
                "enabled": enabled,
            }
        }),
        _ => serde_json::to_value(operation).unwrap_or_else(|_| serde_json::json!({})),
    };
    value.to_string()
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user: AuthUser,
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let row = sqlx::query("select id, username, password_hash, is_admin, must_change_password from dashboard_users where username = ?")
        .bind(&body.username)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::unauthorized("invalid credentials"))?;
    let stored_hash: String = row.get("password_hash");
    if !verify_password(&stored_hash, &body.password) {
        return Err(ApiError::unauthorized("invalid credentials"));
    }
    let user_id: String = row.get("id");
    if is_legacy_password_hash(&stored_hash) {
        sqlx::query("update dashboard_users set password_hash = ? where id = ?")
            .bind(hash_password(&body.password).map_err(|err| ApiError::internal(err.to_string()))?)
            .bind(&user_id)
            .execute(&state.db)
            .await?;
    }
    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::hours(12);
    sqlx::query(
        "insert into sessions (token, user_id, created_at, expires_at) values (?, ?, ?, ?)",
    )
    .bind(&token)
    .bind(&user_id)
    .bind(Utc::now().to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(&state.db)
    .await?;
    let user = AuthUser {
        id: user_id,
        username: row.get("username"),
        is_admin: row.get::<i64, _>("is_admin") == 1,
        must_change_password: row.get::<i64, _>("must_change_password") == 1,
    };
    state
        .audit(&user.username, "auth", "login", "ok", "dashboard login")
        .await?;
    Ok(Json(LoginResponse { token, user }))
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<AuthUser>, ApiError> {
    let user = auth(&headers, &state).await?;
    if body.new_password.len() < 8 {
        return Err(ApiError::bad_request(
            "new password must be at least 8 characters",
        ));
    }
    let current: String =
        sqlx::query_scalar("select password_hash from dashboard_users where id = ?")
            .bind(&user.id)
            .fetch_one(&state.db)
            .await?;
    if !verify_password(&current, &body.current_password) {
        return Err(ApiError::unauthorized("current password is incorrect"));
    }
    sqlx::query(
        "update dashboard_users set password_hash = ?, must_change_password = 0 where id = ?",
    )
    .bind(hash_password(&body.new_password).map_err(|err| ApiError::internal(err.to_string()))?)
    .bind(&user.id)
    .execute(&state.db)
    .await?;
    state
        .audit(
            &user.username,
            "auth",
            "password",
            "ok",
            "dashboard password changed",
        )
        .await?;
    Ok(Json(AuthUser {
        must_change_password: false,
        ..user
    }))
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<AuthUser>, ApiError> {
    Ok(Json(auth(&headers, &state).await?))
}

#[derive(Serialize)]
struct UserListItem {
    id: String,
    username: String,
    is_admin: bool,
    must_change_password: bool,
    created_at: String,
}

async fn count_admins(state: &AppState) -> Result<i64, ApiError> {
    Ok(
        sqlx::query_scalar("select count(*) from dashboard_users where is_admin = 1")
            .fetch_one(&state.db)
            .await?,
    )
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserListItem>>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_admin(&user)?;
    let rows = sqlx::query("select id, username, is_admin, must_change_password, created_at from dashboard_users order by username")
        .fetch_all(&state.db)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| UserListItem {
                id: row.get("id"),
                username: row.get("username"),
                is_admin: row.get::<i64, _>("is_admin") == 1,
                must_change_password: row.get::<i64, _>("must_change_password") == 1,
                created_at: row.get("created_at"),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    is_admin: bool,
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> Result<Json<UserListItem>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    if body.username.trim().is_empty() || body.password.len() < 8 {
        return Err(ApiError::bad_request(
            "username is required and password must be at least 8 characters",
        ));
    }
    let item = UserListItem {
        id: Uuid::new_v4().to_string(),
        username: body.username,
        is_admin: body.is_admin,
        must_change_password: true,
        created_at: Utc::now().to_rfc3339(),
    };
    sqlx::query("insert into dashboard_users (id, username, password_hash, is_admin, must_change_password, created_at) values (?, ?, ?, ?, 1, ?)")
        .bind(&item.id)
        .bind(&item.username)
        .bind(hash_password(&body.password).map_err(|err| ApiError::internal(err.to_string()))?)
        .bind(if item.is_admin { 1 } else { 0 })
        .bind(&item.created_at)
        .execute(&state.db)
        .await?;
    state
        .audit(
            &user.username,
            "users",
            &item.username,
            "ok",
            "dashboard user created",
        )
        .await?;
    Ok(Json(item))
}

#[derive(Deserialize)]
struct UpdateUserRoleRequest {
    is_admin: bool,
}

async fn update_user_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateUserRoleRequest>,
) -> Result<Json<UserListItem>, ApiError> {
    let actor = auth(&headers, &state).await?;
    require_privileged(&actor)?;
    let row = sqlx::query(
        "select id, username, is_admin, must_change_password, created_at from dashboard_users where id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("dashboard user not found"))?;

    let target_was_admin = row.get::<i64, _>("is_admin") == 1;
    if target_was_admin && !body.is_admin && count_admins(&state).await? <= 1 {
        return Err(ApiError::bad_request(
            "cannot demote the last dashboard admin",
        ));
    }

    sqlx::query("update dashboard_users set is_admin = ? where id = ?")
        .bind(if body.is_admin { 1 } else { 0 })
        .bind(&id)
        .execute(&state.db)
        .await?;
    let username: String = row.get("username");
    state
        .audit(
            &actor.username,
            "users",
            &username,
            "ok",
            if body.is_admin {
                "dashboard user promoted"
            } else {
                "dashboard user demoted"
            },
        )
        .await?;
    Ok(Json(UserListItem {
        id: row.get("id"),
        username,
        is_admin: body.is_admin,
        must_change_password: row.get::<i64, _>("must_change_password") == 1,
        created_at: row.get("created_at"),
    }))
}

#[derive(Deserialize)]
struct ResetUserPasswordRequest {
    password: String,
}

async fn reset_user_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ResetUserPasswordRequest>,
) -> Result<Json<UserListItem>, ApiError> {
    let actor = auth(&headers, &state).await?;
    require_privileged(&actor)?;
    if body.password.len() < 8 {
        return Err(ApiError::bad_request(
            "temporary password must be at least 8 characters",
        ));
    }
    let row = sqlx::query(
        "select id, username, is_admin, must_change_password, created_at from dashboard_users where id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("dashboard user not found"))?;
    sqlx::query(
        "update dashboard_users set password_hash = ?, must_change_password = 1 where id = ?",
    )
    .bind(hash_password(&body.password).map_err(|err| ApiError::internal(err.to_string()))?)
    .bind(&id)
    .execute(&state.db)
    .await?;
    sqlx::query("delete from sessions where user_id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    let username: String = row.get("username");
    state
        .audit(
            &actor.username,
            "users",
            &username,
            "ok",
            "dashboard user password reset",
        )
        .await?;
    Ok(Json(UserListItem {
        id: row.get("id"),
        username,
        is_admin: row.get::<i64, _>("is_admin") == 1,
        must_change_password: true,
        created_at: row.get("created_at"),
    }))
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let actor = auth(&headers, &state).await?;
    require_privileged(&actor)?;
    if actor.id == id {
        return Err(ApiError::bad_request(
            "cannot delete your own dashboard user",
        ));
    }
    let row = sqlx::query("select username, is_admin from dashboard_users where id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("dashboard user not found"))?;
    let username: String = row.get("username");
    if row.get::<i64, _>("is_admin") == 1 && count_admins(&state).await? <= 1 {
        return Err(ApiError::bad_request(
            "cannot delete the last dashboard admin",
        ));
    }
    sqlx::query("delete from sessions where user_id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    sqlx::query("delete from dashboard_users where id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    state
        .audit(
            &actor.username,
            "users",
            &username,
            "ok",
            "dashboard user deleted",
        )
        .await?;
    Ok(Json(
        serde_json::json!({ "deleted": id, "username": username }),
    ))
}

async fn storage_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    let data = state
        .helper(&user.username, HelperOperation::ListStorage)
        .await?;
    Ok(Json(data))
}

#[derive(Deserialize)]
struct SetQuotaRequest {
    dataset: String,
    quota: String,
}

async fn set_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SetQuotaRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    validate_dataset_name(&body.dataset)?;
    validate_quota_value(&body.quota)?;
    Ok(Json(
        state
            .helper(
                &user.username,
                HelperOperation::SetQuota {
                    dataset: body.dataset,
                    quota: body.quota,
                },
            )
            .await?,
    ))
}

#[derive(Deserialize)]
struct SnapshotQuery {
    dataset: Option<String>,
}

async fn list_snapshots(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SnapshotQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    if let Some(dataset) = &query.dataset {
        validate_dataset_name(dataset)?;
    }
    Ok(Json(
        state
            .helper(
                &user.username,
                HelperOperation::ListSnapshots {
                    dataset: query.dataset,
                },
            )
            .await?,
    ))
}

#[derive(Deserialize)]
struct CreateSnapshotRequest {
    dataset: String,
    name: String,
}

async fn create_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateSnapshotRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    validate_dataset_name(&body.dataset)?;
    validate_snapshot_label(&body.name)?;
    Ok(Json(
        state
            .helper(
                &user.username,
                HelperOperation::CreateSnapshot {
                    dataset: body.dataset,
                    name: body.name,
                },
            )
            .await?,
    ))
}

async fn delete_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(snapshot): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    validate_snapshot_name(&snapshot)?;
    require_snapshot_confirmation(&headers, &snapshot)?;
    Ok(Json(
        state
            .helper(&user.username, HelperOperation::DeleteSnapshot { snapshot })
            .await?,
    ))
}

async fn rollback_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(snapshot): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    validate_snapshot_name(&snapshot)?;
    require_snapshot_confirmation(&headers, &snapshot)?;
    Ok(Json(
        state
            .helper(
                &user.username,
                HelperOperation::RollbackSnapshot { snapshot },
            )
            .await?,
    ))
}

#[derive(Debug, Deserialize, Serialize)]
struct SambaShare {
    id: Option<String>,
    name: String,
    path: String,
    allowed_users: Vec<String>,
    readonly: bool,
}

async fn list_samba(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_admin(&user)?;
    let rows = sqlx::query("select id, name, path, allowed_users, readonly, created_at from shares_samba order by name")
        .fetch_all(&state.db)
        .await?;
    Ok(Json(rows.into_iter().map(row_to_json).collect()))
}

async fn upsert_samba(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SambaShare>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    validate_share_name(&body.name)?;
    validate_absolute_path(&body.path)?;
    validate_user_list(&body.allowed_users)?;
    let id = body.id.unwrap_or_else(|| Uuid::new_v4().to_string());
    state
        .helper(
            &user.username,
            HelperOperation::ApplySambaShare {
                name: body.name.clone(),
                path: body.path.clone(),
                allowed_users: body.allowed_users.clone(),
                readonly: body.readonly,
            },
        )
        .await?;
    sqlx::query("insert into shares_samba (id, name, path, allowed_users, readonly, created_at) values (?, ?, ?, ?, ?, ?)
        on conflict(id) do update set name = excluded.name, path = excluded.path, allowed_users = excluded.allowed_users, readonly = excluded.readonly")
        .bind(&id)
        .bind(&body.name)
        .bind(&body.path)
        .bind(serde_json::to_string(&body.allowed_users).unwrap_or_else(|_| "[]".into()))
        .bind(if body.readonly { 1 } else { 0 })
        .bind(Utc::now().to_rfc3339())
        .execute(&state.db)
        .await?;
    state
        .audit(
            &user.username,
            "samba",
            &body.name,
            "ok",
            "samba share saved",
        )
        .await?;
    Ok(Json(serde_json::json!({ "id": id })))
}

async fn delete_samba(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    let name: String = sqlx::query_scalar("select name from shares_samba where id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("samba share not found"))?;
    state
        .helper(
            &user.username,
            HelperOperation::DeleteSambaShare { name: name.clone() },
        )
        .await?;
    sqlx::query("delete from shares_samba where id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    state
        .audit(&user.username, "samba", &name, "ok", "samba share deleted")
        .await?;
    Ok(Json(serde_json::json!({ "deleted": id, "name": name })))
}

#[derive(Debug, Deserialize)]
struct SambaUserRequest {
    username: String,
    password: String,
    enabled: bool,
}

async fn list_samba_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_admin(&user)?;
    let rows = sqlx::query(
        "select username, enabled, created_at, updated_at from samba_users order by username",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.into_iter().map(row_to_json).collect()))
}

async fn upsert_samba_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SambaUserRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    validate_storage_username(&body.username)?;
    if body.password.len() < 8 {
        return Err(ApiError::bad_request(
            "samba password must be at least 8 characters",
        ));
    }
    state
        .helper(
            &user.username,
            HelperOperation::UpsertSambaUser {
                username: body.username.clone(),
                password: body.password,
                enabled: body.enabled,
            },
        )
        .await?;
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "insert into samba_users (username, enabled, created_at, updated_at) values (?, ?, ?, ?)
         on conflict(username) do update set enabled = excluded.enabled, updated_at = excluded.updated_at",
    )
    .bind(&body.username)
    .bind(if body.enabled { 1 } else { 0 })
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await?;
    state
        .audit(
            &user.username,
            "samba_user",
            &body.username,
            "ok",
            "samba user saved",
        )
        .await?;
    Ok(Json(serde_json::json!({
        "username": body.username,
        "enabled": body.enabled,
    })))
}

async fn delete_samba_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    validate_storage_username(&username)?;
    state
        .helper(
            &user.username,
            HelperOperation::DeleteSambaUser {
                username: username.clone(),
            },
        )
        .await?;
    sqlx::query("delete from samba_users where username = ?")
        .bind(&username)
        .execute(&state.db)
        .await?;
    state
        .audit(
            &user.username,
            "samba_user",
            &username,
            "ok",
            "samba user deleted",
        )
        .await?;
    Ok(Json(serde_json::json!({ "deleted": username })))
}

#[derive(Debug, Deserialize, Serialize)]
struct NfsShare {
    id: Option<String>,
    path: String,
    clients: String,
    options: String,
}

async fn list_nfs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_admin(&user)?;
    let rows =
        sqlx::query("select id, path, clients, options, created_at from shares_nfs order by path")
            .fetch_all(&state.db)
            .await?;
    Ok(Json(rows.into_iter().map(row_to_json).collect()))
}

async fn upsert_nfs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NfsShare>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    validate_absolute_path(&body.path)?;
    reject_shell_chars(&body.clients, "clients")?;
    reject_shell_chars(&body.options, "options")?;
    let id = body.id.unwrap_or_else(|| Uuid::new_v4().to_string());
    state
        .helper(
            &user.username,
            HelperOperation::ApplyNfsExport {
                path: body.path.clone(),
                clients: body.clients.clone(),
                options: body.options.clone(),
            },
        )
        .await?;
    sqlx::query("insert into shares_nfs (id, path, clients, options, created_at) values (?, ?, ?, ?, ?)
        on conflict(id) do update set path = excluded.path, clients = excluded.clients, options = excluded.options")
        .bind(&id)
        .bind(&body.path)
        .bind(&body.clients)
        .bind(&body.options)
        .bind(Utc::now().to_rfc3339())
        .execute(&state.db)
        .await?;
    state
        .audit(&user.username, "nfs", &body.path, "ok", "nfs export saved")
        .await?;
    Ok(Json(serde_json::json!({ "id": id })))
}

async fn delete_nfs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    let path: String = sqlx::query_scalar("select path from shares_nfs where id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("nfs export not found"))?;
    state
        .helper(
            &user.username,
            HelperOperation::DeleteNfsExport { path: path.clone() },
        )
        .await?;
    sqlx::query("delete from shares_nfs where id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    state
        .audit(&user.username, "nfs", &path, "ok", "nfs export deleted")
        .await?;
    Ok(Json(serde_json::json!({ "deleted": id, "path": path })))
}

fn row_to_json(row: sqlx::sqlite::SqliteRow) -> serde_json::Value {
    let mut value = BTreeMap::new();
    for column in row.columns() {
        let name = column.name();
        if let Ok(v) = row.try_get::<String, _>(name) {
            value.insert(name.to_string(), serde_json::Value::String(v));
        } else if let Ok(v) = row.try_get::<i64, _>(name) {
            value.insert(name.to_string(), serde_json::Value::Number(v.into()));
        }
    }
    serde_json::to_value(value).unwrap_or_else(|_| serde_json::json!({}))
}

async fn list_services(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let user = auth(&headers, &state).await?;
    let mut services = Vec::new();
    for (name, label) in [
        ("zfs", "ZFS"),
        ("samba_server", "Samba"),
        ("nfsd", "NFS"),
        ("ctld", "iSCSI Target"),
        ("syslogd", "System Logs"),
    ] {
        let mut data = state
            .helper(
                &user.username,
                HelperOperation::ServiceStatus {
                    service: name.into(),
                },
            )
            .await?;
        data["name"] = serde_json::Value::String(name.into());
        data["label"] = serde_json::Value::String(label.into());
        services.push(data);
    }
    Ok(Json(services))
}

async fn service_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((service, action)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_privileged(&user)?;
    if !allowed_service(&service) {
        return Err(ApiError::bad_request("service is not allowlisted"));
    }
    let action = match action.as_str() {
        "start" => ServiceAction::Start,
        "stop" => ServiceAction::Stop,
        "restart" => ServiceAction::Restart,
        _ => {
            return Err(ApiError::bad_request(
                "service action must be start, stop, or restart",
            ))
        }
    };
    Ok(Json(
        state
            .helper(
                &user.username,
                HelperOperation::ServiceAction { service, action },
            )
            .await?,
    ))
}

#[derive(Deserialize)]
struct LogQuery {
    service: Option<String>,
    severity: Option<String>,
    search: Option<String>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

async fn logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LogQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth(&headers, &state).await?;
    let _date_range = (query.from, query.to);
    Ok(Json(
        state
            .helper(
                &user.username,
                HelperOperation::ReadLogs {
                    service: query.service,
                    severity: query.severity,
                    search: query.search,
                    from: query.from,
                    to: query.to,
                },
            )
            .await?,
    ))
}

async fn audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_admin(&user)?;
    let rows = sqlx::query("select id, actor, category, target, result, message, created_at from audit_events order by created_at desc limit 200")
        .fetch_all(&state.db)
        .await?;
    Ok(Json(rows.into_iter().map(row_to_json).collect()))
}

async fn helper_history(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let user = auth(&headers, &state).await?;
    require_admin(&user)?;
    let rows = sqlx::query(
        "select id, actor, operation, ok, message, created_at from helper_history order by created_at desc limit 200",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.into_iter().map(row_to_json).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn test_app() -> Router {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let state = AppState::new(pool, Arc::new(bnasmgr_helper::MockHelper));
        state.migrate().await.unwrap();
        state.seed_admin().await.unwrap();
        app(state)
    }

    async fn login_admin(app: Router) -> (Router, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"admin"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let login: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = login["token"].as_str().unwrap().to_string();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/change-password")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"current_password":"admin","new_password":"adminadmin"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        (app, token)
    }

    #[tokio::test]
    async fn seeded_admin_must_change_password_before_privileged_actions() {
        let app = test_app().await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"admin"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let login: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(login["user"]["must_change_password"], true);
        let token = login["token"].as_str().unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/snapshots")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"dataset":"tank/media","name":"now"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn password_hashes_use_argon2_and_legacy_hashes_still_verify() {
        let modern = hash_password("correct horse battery staple").unwrap();
        assert!(modern.starts_with("$argon2"));
        assert!(verify_password(&modern, "correct horse battery staple"));
        assert!(!verify_password(&modern, "wrong"));

        let legacy = legacy_hash_password("admin");
        assert!(is_legacy_password_hash(&legacy));
        assert!(verify_password(&legacy, "admin"));
    }

    #[tokio::test]
    async fn share_inputs_reject_shell_control_characters() {
        let (app, token) = login_admin(test_app().await).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shares/samba")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"bad;name","path":"/mnt/tank/media","allowed_users":["alice"],"readonly":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn user_management_allows_reset_role_and_delete_with_safety_guards() {
        let (app, token) = login_admin(test_app().await).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"operator","password":"temporary","is_admin":false}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let operator_id = created["id"].as_str().unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/users/{operator_id}/role"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"is_admin":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/users/{operator_id}/reset-password"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"replacement"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/users/{operator_id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/auth/me")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cannot_delete_self_or_demote_last_admin() {
        let (app, token) = login_admin(test_app().await).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/auth/me")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let me: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let admin_id = me["id"].as_str().unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/users/{admin_id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/users/{admin_id}/role"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"is_admin":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn service_actions_are_allowlisted() {
        let (app, token) = login_admin(test_app().await).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/services/sshd/restart")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn quota_values_are_validated_by_api() {
        let (app, token) = login_admin(test_app().await).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/storage/quota")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"dataset":"tank/media","quota":"../../bad"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn helper_history_is_exposed_to_admins() {
        let (app, token) = login_admin(test_app().await).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/storage/overview")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/audit/helper-history")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let history: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(history[0]["actor"], "admin");
        assert!(history[0]["operation"]
            .as_str()
            .unwrap()
            .contains("list_storage"));
    }

    #[tokio::test]
    async fn samba_user_passwords_are_redacted_from_helper_history() {
        let (app, token) = login_admin(test_app().await).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/shares/samba/users")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"alice","password":"supersecret","enabled":true}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/audit/helper-history")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let history: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let operation = history[0]["operation"].as_str().unwrap();
        assert!(operation.contains("<redacted>"));
        assert!(!operation.contains("supersecret"));
    }

    #[tokio::test]
    async fn destructive_snapshot_operations_require_exact_confirmation() {
        let (app, token) = login_admin(test_app().await).await;
        let snapshot = "tank/media@daily-2026-05-18";
        let encoded = "tank%2Fmedia%40daily-2026-05-18";

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/snapshots/{encoded}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/snapshots/{encoded}"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-bnasmgr-confirm", snapshot)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/snapshots/{encoded}/rollback"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-bnasmgr-confirm", snapshot)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
