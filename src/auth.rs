use crate::errors::AppError;
use crate::rate_limit::RateLimiter;
use crate::token_manager::{sha256_hex, TokenManager};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// Shared auth state — DB-backed token manager + rate limiter.
#[derive(Clone)]
pub struct AuthState {
    pub token_manager: Arc<TokenManager>,
    pub rate_limiter: Arc<RateLimiter>,
}

/// Build the auth state.
pub fn build_auth_state(
    token_manager: Arc<TokenManager>,
    rate_limiter: Arc<RateLimiter>,
) -> AuthState {
    AuthState {
        token_manager,
        rate_limiter,
    }
}

/// Identifies the operator who made the request.
/// Value: first 12 hex chars of the token's SHA-256 hash.
/// Inserted as an Axum extension by require_bearer after successful auth.
#[derive(Clone, Debug)]
pub struct OperatorId(pub String);

/// Client IP address extracted from ConnectInfo<SocketAddr>.
/// Inserted as an Axum extension by require_bearer after successful auth.
#[derive(Clone, Debug)]
pub struct ClientIp(pub Option<std::net::IpAddr>);

/// Axum middleware: validate the Authorization: Bearer <token> header against
/// the DB-backed token cache, then enforce per-token rate limits.
///
/// Returns 401 UNAUTHORIZED if the token is missing or not active in the DB.
/// Returns 429 RATE_LIMIT_EXCEEDED if the token has exceeded its per-second quota.
///
/// After successful validation, updates `last_used_at` in a fire-and-forget
/// background task (debounced to at most once per minute per token).
///
/// Inserts `OperatorId` and `ClientIp` as Axum extensions for downstream handlers.
pub async fn require_bearer(
    State(auth): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer(req.headers())?.to_owned();
    if !auth.token_manager.is_valid(&token) {
        return Err(AppError::Unauthorized);
    }
    auth.rate_limiter.check(&token)?;
    auth.token_manager.bump_last_used(&token);

    // Derive OperatorId: first 12 hex chars of the SHA-256 of the raw token.
    let token_hash_prefix = sha256_hex(&token).chars().take(12).collect::<String>();
    req.extensions_mut().insert(OperatorId(token_hash_prefix));

    // Extract client IP from ConnectInfo extension (inserted by into_make_service_with_connect_info).
    let client_ip: Option<std::net::IpAddr> = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());
    req.extensions_mut().insert(ClientIp(client_ip));

    Ok(next.run(req).await)
}

/// Axum middleware: reject requests where the token role is not 'owner'.
///
/// Must run after require_bearer (depends on valid bearer token being present).
/// Returns 403 Forbidden if the token is not an owner token.
pub async fn require_owner(
    State(auth): State<AuthState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer(req.headers())?.to_owned();
    let role = auth.token_manager.get_token_role(&token).await;
    match role.as_deref() {
        Some("owner") => Ok(next.run(req).await),
        _ => Err(AppError::Forbidden),
    }
}

fn extract_bearer(headers: &axum::http::HeaderMap) -> Result<&str, AppError> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(AppError::Unauthorized)?
        .to_str()
        .map_err(|_| AppError::Unauthorized)?;

    header.strip_prefix("Bearer ").ok_or(AppError::Unauthorized)
}
