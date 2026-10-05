pub mod asset;
pub mod attestation;
pub mod audit;
pub mod auth;
pub mod backfill;
pub mod binding;
pub mod config;
pub mod db;
pub mod encryption;
pub mod errors;
pub mod evidence;
pub mod exposure;
pub mod gdpr;
pub mod heartbeat;
pub mod kms;
pub mod layer2;
pub mod merkle;
pub mod merkle_v2;
pub mod metrics;
pub mod middleware;
pub mod mta;
pub mod openapi;
pub mod policy;
pub mod rate_limit;
pub mod registry;
pub mod routes;
pub mod seal;
pub mod seal_v2;
pub mod shadow_mode;
pub mod snapshot;
pub mod time;
pub mod tls;
pub mod token_manager;
pub mod verifier;
pub mod webhook;

use std::sync::Arc;
pub use token_manager::TokenManager;

use auth::build_auth_state;
use axum::{
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{delete, get, patch, post},
    Extension, Router,
};
use heartbeat::HeartbeatValidator;
use middleware::client_cert::{client_cert_middleware, PeerCertDer};
use mta::MtaClient;
use rate_limit::RateLimiter;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Shared application state injected into all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::Config>,
    pub pool: sqlx::PgPool,
    /// DB-02: optional read-replica pool for analytics SELECT routes.
    /// When DB_READONLY_URL is set, analytics GET routes use this pool.
    /// Falls back to primary `pool` when None.
    pub readonly_pool: Option<sqlx::PgPool>,
    pub heartbeat_validator: Arc<HeartbeatValidator>,
    /// The active Market Truth Anchor client.
    /// Any type implementing MtaClient can be substituted here without
    /// touching route handlers or the policy engine.
    pub mta_client: Arc<dyn MtaClient>,
    /// KMS envelope key provider. None = plaintext mode (encryption_version=0).
    pub key_provider: Option<Arc<dyn kms::KeyProvider>>,
    /// DB-backed shadow mode cache. Hot-path reads are O(1) AtomicBool reads.
    /// Background refresh keeps it in sync with `irl.system_config` every 30 s.
    pub shadow_mode: Arc<shadow_mode::ShadowModeCache>,
    /// DB-backed token manager. Used by admin token endpoints to issue/revoke
    /// tokens and refresh the in-memory cache immediately.
    pub token_manager: Arc<TokenManager>,
    /// Server TLS certificate expiry time. Populated by main.rs when TLS is active.
    /// Used by the health endpoint to surface cert_expiry_status.
    pub cert_expiry_not_after: Option<std::time::SystemTime>,
}

/// Build the application router from a fully initialised `AppState`.
///
/// Separating router construction from `main` lets integration tests build
/// the same app against a real database without starting a TCP listener.
pub fn build_router(state: AppState) -> Router {
    let rate_limiter = RateLimiter::new(state.config.rate_limit_per_second);
    let auth_state = build_auth_state(state.token_manager.clone(), rate_limiter);
    let max_body = state.config.max_body_bytes;

    let protected = Router::new()
        .route("/irl/authorize", post(routes::authorize::authorize))
        .route("/irl/authorize/batch", post(routes::batch::batch_authorize))
        .route("/irl/bind-execution", post(routes::bind::bind_execution))
        .route("/irl/trace/:trace_id", get(routes::get_trace))
        .route(
            "/irl/trace/:trace_id/chain",
            get(routes::chain::get_trace_chain),
        )
        .route("/irl/pending", get(routes::get_pending))
        .route("/irl/regime", get(routes::regime))
        .route("/irl/orphans", get(routes::get_orphans))
        .route("/irl/agents", post(routes::agents::register_agent))
        .route("/irl/agents/:id", get(routes::agents::get_agent))
        .route(
            "/irl/agents/:id/status",
            patch(routes::agents::update_agent_status),
        )
        .route("/irl/shadow-violations", get(routes::get_shadow_violations))
        .route("/irl/traces", get(routes::traces::list_traces))
        .route(
            "/irl/attestation",
            get(routes::attestation::get_attestation),
        )
        .layer(axum_middleware::from_fn_with_state(
            auth_state.clone(),
            auth::require_bearer,
        ));

    // Owner-only admin routes — require_owner runs after require_bearer.
    // Layers are applied bottom-up, so require_bearer is the outer layer.
    let admin_routes = Router::new()
        .route(
            "/irl/admin/shadow-mode",
            get(routes::admin::shadow_mode_get),
        )
        .route(
            "/irl/admin/shadow-mode",
            post(routes::admin::shadow_mode_set),
        )
        .route("/irl/admin/audit-log", get(routes::admin::audit_log_query))
        .route(
            "/irl/admin/gdpr-erase/:agent_id",
            post(routes::admin::gdpr_erase_handler),
        )
        .route("/irl/admin/tokens", post(routes::tokens::token_issue))
        .route(
            "/irl/admin/tokens/:token_id",
            delete(routes::tokens::token_revoke),
        )
        .route("/irl/admin/evidence", get(routes::admin::evidence_export))
        .route("/irl/agents", get(routes::agents::list_agents))
        .layer(axum_middleware::from_fn_with_state(
            auth_state.clone(),
            auth::require_owner,
        ))
        .layer(axum_middleware::from_fn_with_state(
            auth_state,
            auth::require_bearer,
        ));

    let public = Router::new()
        .route("/", get(routes::landing))
        .route("/irl/health", get(routes::health))
        .route("/irl/anchors", get(routes::attestation::list_anchors))
        .route("/metrics", get(routes::metrics_handler));

    // OpenAPI spec + Swagger UI publish the full API catalog with NO auth. Gate
    // behind EXPOSE_DOCS (default OFF) so a self-hosted / prod origin is not
    // enumerable by anyone hitting the raw host. The public demo/sandbox sets
    // EXPOSE_DOCS=true to keep interactive docs available.
    let docs_enabled = std::env::var("EXPOSE_DOCS")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    let public = if docs_enabled {
        public.merge(SwaggerUi::new("/swagger-ui").url("/openapi.json", openapi::ApiDoc::openapi()))
    } else {
        public
    };

    public
        .merge(protected)
        .merge(admin_routes)
        .layer(axum_middleware::from_fn(client_cert_middleware))
        .layer(Extension(PeerCertDer::default()))
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}
