//! POST /irl/authorize/batch
//!
//! Authorize up to 50 trade intents in a single round-trip. Each item in the
//! `requests` array is a full AuthorizeRequest (including its own heartbeat).
//! Results are returned in the same order as the input. Per-item errors are
//! embedded inline so one failing request does not abort the rest.
//!
//! Response shape:
//! ```json
//! {
//!   "count": 3,
//!   "results": [
//!     { "trace_id": "...", "reasoning_hash": "...", "authorized": true, "shadow_blocked": false },
//!     { "error": "REGIME_VIOLATION", "message": "..." },
//!     { "trace_id": "...", "authorized": true, ... }
//!   ]
//! }
//! ```

use crate::errors::AppError;
use crate::middleware::client_cert::ClientCertInfo;
use crate::snapshot::AuthorizeRequest;
use crate::AppState;
use axum::{extract::State, Extension, Json};
use serde::Deserialize;

const BATCH_MAX_SIZE: usize = 50;

#[derive(Debug, Deserialize)]
pub struct BatchAuthorizeRequest {
    pub requests: Vec<AuthorizeRequest>,
}

/// POST /irl/authorize/batch
pub async fn batch_authorize(
    State(state): State<AppState>,
    cert_ext: Option<Extension<ClientCertInfo>>,
    Json(batch): Json<BatchAuthorizeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if batch.requests.is_empty() {
        return Err(AppError::BadRequest(
            "requests array must not be empty".into(),
        ));
    }
    if batch.requests.len() > BATCH_MAX_SIZE {
        return Err(AppError::BadRequest(format!(
            "Batch size {} exceeds maximum of {BATCH_MAX_SIZE}",
            batch.requests.len()
        )));
    }

    let cert_info = cert_ext.map(|e| e.0);
    let mut results = Vec::with_capacity(batch.requests.len());

    for req in batch.requests {
        let outcome = match super::authorize::authorize_one(&state, cert_info.as_ref(), req).await {
            Ok(v) => v,
            Err(e) => serde_json::json!({
                "error": e.error_code(),
                "message": e.to_string(),
            }),
        };
        results.push(outcome);
    }

    Ok(Json(serde_json::json!({
        "count": results.len(),
        "results": results,
    })))
}
