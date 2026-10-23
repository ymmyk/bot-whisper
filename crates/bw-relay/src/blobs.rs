//! Encrypted file blobs: ciphertext the connector uploads for a room, which
//! members fetch and ack. The relay never sees the file key, name, size or
//! hash (they travel inside the MLS message) and never logs a blob. Blobs
//! live on disk under the data directory until every recipient acked or
//! the TTL passed (`BW_FILE_TTL`); a background sweeper deletes the rest.
//!
//! Routes (bearer auth like `/mcp`, so the caller is a seated bot):
//!
//! - `PUT  /e2e/blobs/{room_id}`                raw ciphertext body → `{blob_id, size, expires_at, pending}`
//! - `GET  /e2e/blobs/{room_id}/{blob_id}`      the ciphertext (`application/octet-stream`)
//! - `POST /e2e/blobs/{room_id}/{blob_id}/ack`  → `{acked, deleted}`

// Handlers return a ready `Response` as the error branch; that is the
// idiomatic axum shape and the size is irrelevant on this path.
#![allow(clippy::result_large_err)]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Extension, Path as AxPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, put},
    Router,
};
use bw_proto::ErrorCode;
use serde_json::json;

use crate::{
    auth::{require_bearer, AgentId, TokenAuth},
    db::{BlobRow, Db},
    doorbell::now_unix,
    error::RelayError,
    http::AppState,
};

/// Default size cap: 10 MiB.
pub const DEFAULT_MAX_FILE_BYTES: usize = 10 * 1024 * 1024;
/// Default time to live: 7 days.
pub const DEFAULT_FILE_TTL_SECS: u64 = 7 * 24 * 3600;

/// Where blob files go for this configuration.
pub fn blob_dir(cfg: &crate::config::RelayConfig) -> PathBuf {
    if let Some(d) = &cfg.blob_dir {
        return d.clone();
    }
    match &cfg.db_path {
        Some(p) => p.parent().unwrap_or(Path::new(".")).join("blobs"),
        None => std::env::temp_dir().join(format!("botwhisper-blobs-{}", std::process::id())),
    }
}

fn blob_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(id)
}

fn problem(status: StatusCode, e: RelayError) -> Response {
    (status, Json(e.to_json())).into_response()
}

fn status_for(e: &RelayError) -> StatusCode {
    match e.code {
        ErrorCode::NotAMember | ErrorCode::Unauthorized => StatusCode::FORBIDDEN,
        ErrorCode::RoomClosed => StatusCode::NOT_FOUND,
        ErrorCode::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// The blob routes, authenticated like `/mcp`.
pub fn router(state: AppState, auth: TokenAuth) -> Router {
    let limit = state.cfg.max_file_bytes;
    Router::new()
        .route("/e2e/blobs/{room_id}", put(upload))
        .route("/e2e/blobs/{room_id}/{blob_id}", get(download))
        .route(
            "/e2e/blobs/{room_id}/{blob_id}/ack",
            axum::routing::post(ack),
        )
        .layer(DefaultBodyLimit::max(limit))
        .route_layer(axum::middleware::from_fn_with_state(auth, require_bearer))
        .with_state(state)
}

/// The caller's active seat in the room, plus the current active roster.
async fn seat(
    state: &AppState,
    agent: &AgentId,
    room_id: &str,
) -> Result<(String, Vec<String>), RelayError> {
    let (room, me) = state.registry.resolve(agent, room_id).await?;
    if !me.is_e2e_active() {
        return Err(RelayError::new(
            ErrorCode::Unauthorized,
            "you are not in the group yet (pending_join)",
        ));
    }
    let active = room
        .with(|r| {
            r.members()
                .iter()
                .filter(|m| m.is_e2e_active())
                .map(|m| m.member.clone())
                .collect::<Vec<_>>()
        })
        .await?;
    Ok((me.member, active))
}

async fn upload(
    State(state): State<AppState>,
    Extension(agent): Extension<AgentId>,
    AxPath(room_id): AxPath<String>,
    body: Bytes,
) -> Response {
    let max = state.cfg.max_file_bytes;
    if body.is_empty() || body.len() > max {
        return problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            RelayError::new(
                ErrorCode::BodyTooLarge,
                format!("file ciphertext must be 1 to {max} bytes"),
            )
            .with_data(json!({ "max_file_bytes": max })),
        );
    }
    let (me, active) = match seat(&state, &agent, &room_id).await {
        Ok(v) => v,
        Err(e) => return problem(status_for(&e), e),
    };
    let pending: Vec<String> = active.into_iter().filter(|m| m != &me).collect();
    let now = now_unix();
    let row = BlobRow {
        id: uuid::Uuid::new_v4().simple().to_string(),
        room_id: room_id.clone(),
        uploader: me,
        size: body.len() as u64,
        created_at: now,
        expires_at: now + state.cfg.file_ttl.as_secs(),
        pending: pending.clone(),
    };
    let dir = blob_dir(&state.cfg);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            RelayError::internal(format!("blob storage: {e}")),
        );
    }
    if let Err(e) = write_private(&blob_path(&dir, &row.id), &body) {
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            RelayError::internal(format!("blob storage: {e}")),
        );
    }
    if let Err(e) = state.registry.db.insert_blob(&row) {
        let _ = std::fs::remove_file(blob_path(&dir, &row.id));
        return problem(StatusCode::INTERNAL_SERVER_ERROR, e.into());
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "blob_id": row.id,
            "size": row.size,
            "expires_at": row.expires_at,
            "pending": pending,
        })),
    )
        .into_response()
}

async fn load(
    state: &AppState,
    agent: &AgentId,
    room_id: &str,
    blob_id: &str,
) -> Result<(String, BlobRow), Response> {
    let (me, _) = seat(state, agent, room_id)
        .await
        .map_err(|e| problem(status_for(&e), e))?;
    let row = state
        .registry
        .db
        .get_blob(blob_id)
        .map_err(|e| problem(StatusCode::INTERNAL_SERVER_ERROR, e.into()))?
        .filter(|r| r.room_id == room_id && r.expires_at > now_unix())
        .ok_or_else(|| {
            problem(
                StatusCode::NOT_FOUND,
                RelayError::invalid("no such file (it may have expired or been collected)"),
            )
        })?;
    Ok((me, row))
}

async fn download(
    State(state): State<AppState>,
    Extension(agent): Extension<AgentId>,
    AxPath((room_id, blob_id)): AxPath<(String, String)>,
) -> Response {
    let (_me, row) = match load(&state, &agent, &room_id, &blob_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match std::fs::read(blob_path(&blob_dir(&state.cfg), &row.id)) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(_) => problem(
            StatusCode::NOT_FOUND,
            RelayError::invalid("no such file (it may have expired or been collected)"),
        ),
    }
}

async fn ack(
    State(state): State<AppState>,
    Extension(agent): Extension<AgentId>,
    AxPath((room_id, blob_id)): AxPath<(String, String)>,
) -> Response {
    let (me, row) = match load(&state, &agent, &room_id, &blob_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let remaining = match state.registry.db.ack_blob(&row.id, &me) {
        Ok(n) => n,
        Err(e) => return problem(StatusCode::INTERNAL_SERVER_ERROR, e.into()),
    };
    let deleted = remaining == 0;
    if deleted {
        delete_blob(&state.registry.db, &blob_dir(&state.cfg), &row.id);
    }
    Json(json!({ "acked": true, "deleted": deleted, "pending": remaining })).into_response()
}

/// Remove a blob's file and row.
pub fn delete_blob(db: &Db, dir: &Path, id: &str) {
    let _ = std::fs::remove_file(blob_path(dir, id));
    let _ = db.delete_blob(id);
}

/// Drop every blob of a room (the room closed).
pub fn delete_room_blobs(db: &Db, dir: &Path, room_id: &str) {
    if let Ok(ids) = db.room_blob_ids(room_id) {
        for id in ids {
            delete_blob(db, dir, &id);
        }
    }
}

/// Delete expired blobs. Returns how many.
pub fn sweep(db: &Db, dir: &Path, now: u64) -> usize {
    let ids = db.expired_blob_ids(now).unwrap_or_default();
    for id in &ids {
        delete_blob(db, dir, id);
    }
    ids.len()
}

/// Run the sweeper until `shutdown`.
pub fn spawn_sweeper(
    db: Db,
    cfg: Arc<crate::config::RelayConfig>,
    every: std::time::Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let dir = blob_dir(&cfg);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let n = sweep(&db, &dir, now_unix());
                    if n > 0 {
                        tracing::debug!(count = n, "expired file blobs removed");
                    }
                }
                _ = shutdown.cancelled() => break,
            }
        }
    });
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}
