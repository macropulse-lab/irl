/// OpenAPI 3.1 specification for the IRL Engine HTTP API.
///
/// Exposed at:
///   GET /openapi.json   — machine-readable spec
///   GET /swagger-ui/    — interactive browser UI (development / demo)
use crate::binding::{BindExecutionRequest, BindExecutionResult, VerificationStatus};
use crate::heartbeat::SignedHeartbeat;
use crate::snapshot::{
    AgentBlock, AuthorizeRequest, BiTemporalBlock, ExecutionBlock, HeartbeatBlock, IntegrityBlock,
    MtaBlock, PolicyBlock, ReasoningTrace, RegulatoryBlock,
};
use utoipa::OpenApi;

#[utoipa::path(
    post,
    path = "/irl/authorize",
    tag = "Core",
    request_body = AuthorizeRequest,
    responses(
        (status = 200, description = "Authorized — reasoning_hash issued", body = AuthorizeResponse),
        (status = 403, description = "Policy violation or mTLS CN mismatch"),
        (status = 422, description = "Validation error"),
    ),
    security(("bearer_token" = []))
)]
pub fn authorize() {}

/// Response for POST /irl/authorize.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct AuthorizeResponse {
    pub trace_id: uuid::Uuid,
    pub reasoning_hash: String,
    pub authorized: bool,
    pub shadow_blocked: bool,
}

#[utoipa::path(
    post,
    path = "/irl/bind-execution",
    tag = "Core",
    request_body = BindExecutionRequest,
    responses(
        (status = 200, description = "Bound — final_proof computed", body = BindExecutionResult),
        (status = 404, description = "Trace not found"),
        (status = 409, description = "Trace already bound"),
        (status = 422, description = "Validation error"),
    ),
    security(("bearer_token" = []))
)]
pub fn bind_execution() {}

#[utoipa::path(
    get,
    path = "/irl/trace/{trace_id}",
    tag = "Traces",
    params(
        ("trace_id" = uuid::Uuid, Path, description = "UUID of the reasoning trace")
    ),
    responses(
        (status = 200, description = "Reasoning_Trace_v1", body = ReasoningTrace),
        (status = 404, description = "Trace not found"),
    ),
    security(("bearer_token" = []))
)]
pub fn get_trace() {}

#[utoipa::path(
    get,
    path = "/irl/traces",
    tag = "Traces",
    params(
        ("agent_id" = Option<String>, Query, description = "Filter by agent UUID"),
        ("from" = Option<i64>, Query, description = "Start of time range (Unix ms)"),
        ("to" = Option<i64>, Query, description = "End of time range (Unix ms)"),
        ("status" = Option<String>, Query,
         description = "PENDING|MATCHED|DIVERGENT|ORPHAN|EXPIRED|SHADOW_HALTED"),
        ("limit" = Option<i64>, Query, description = "Max results (default 500, max 5000)"),
    ),
    responses(
        (status = 200, description = "Filtered trace list", body = TraceListResponse),
    ),
    security(("bearer_token" = []))
)]
pub fn list_traces() {}

#[utoipa::path(
    get,
    path = "/irl/health",
    tag = "Operations",
    responses(
        (status = 200, description = "Engine healthy", body = HealthResponse),
        (status = 503, description = "Engine not ready"),
    )
)]
pub fn health() {}

#[utoipa::path(
    get,
    path = "/irl/pending",
    tag = "Traces",
    params(
        ("age_seconds" = Option<i64>, Query,
         description = "Only return traces older than this many seconds (default 3600)")
    ),
    responses(
        (status = 200, description = "Stale PENDING traces", body = TraceListResponse),
    ),
    security(("bearer_token" = []))
)]
pub fn get_pending() {}

#[utoipa::path(
    get,
    path = "/irl/orphans",
    tag = "Traces",
    responses(
        (status = 200, description = "DIVERGENT and EXPIRED traces", body = TraceListResponse),
    ),
    security(("bearer_token" = []))
)]
pub fn get_orphans() {}

#[utoipa::path(
    get,
    path = "/irl/shadow-violations",
    tag = "Operations",
    responses(
        (status = 200, description = "SHADOW_HALTED traces", body = TraceListResponse),
    ),
    security(("bearer_token" = []))
)]
pub fn get_shadow_violations() {}

#[utoipa::path(
    get,
    path = "/irl/attestation",
    tag = "Verification",
    params(
        ("from" = String, Query, description = "Start of period, RFC 3339 (exclusive), e.g. 2026-05-01T00:00:00Z"),
        ("to" = String, Query, description = "End of period, RFC 3339 (inclusive)"),
        ("agent_id" = Option<uuid::Uuid>, Query, description = "Restrict traces to a single agent"),
    ),
    responses(
        (status = 200, description = "Self-contained proof bundle: every trace in the period plus \
            every overlapping Merkle anchor with its full ordered leaf list and OpenTimestamps \
            receipt (base64). Verify fully offline with the `irl-verify` CLI — no network, no \
            database, no trust in the IRL operator."),
        (status = 400, description = "Invalid range, or bundle would exceed the trace cap"),
    ),
    security(("bearer_token" = []))
)]
pub fn get_attestation() {}

#[utoipa::path(
    get,
    path = "/irl/anchors",
    tag = "Verification",
    responses(
        (status = 200, description = "Public Merkle anchor transparency feed: last 100 daily \
            anchors with period bounds, leaf count, root hex, and OpenTimestamps status. \
            No authentication required — roots reveal nothing about trace contents."),
    )
)]
pub fn list_anchors() {}

#[utoipa::path(
    get,
    path = "/irl/admin/shadow-mode",
    tag = "Admin",
    responses(
        (status = 200, description = "Current shadow mode state"),
    ),
    security(("bearer_token" = []))
)]
pub fn shadow_mode_get() {}

#[utoipa::path(
    post,
    path = "/irl/admin/shadow-mode",
    tag = "Admin",
    request_body = ShadowModeRequest,
    responses(
        (status = 200, description = "Shadow mode updated"),
    ),
    security(("bearer_token" = []))
)]
pub fn shadow_mode_set() {}

#[utoipa::path(
    get,
    path = "/irl/admin/audit-log",
    tag = "Admin",
    params(
        ("action" = Option<String>, Query, description = "Filter by action type"),
        ("target_id" = Option<String>, Query, description = "Filter by target UUID"),
        ("from" = Option<String>, Query, description = "ISO 8601 start datetime"),
        ("to" = Option<String>, Query, description = "ISO 8601 end datetime"),
        ("before_id" = Option<String>, Query, description = "Cursor (UUID of last seen entry)"),
        ("limit" = Option<i64>, Query, description = "Max results (default 100, max 1000)"),
    ),
    responses(
        (status = 200, description = "Audit log entries"),
    ),
    security(("bearer_token" = []))
)]
pub fn audit_log_query() {}

#[utoipa::path(
    post,
    path = "/irl/admin/gdpr-erase/{agent_id}",
    tag = "Admin",
    params(
        ("agent_id" = uuid::Uuid, Path, description = "Agent UUID to erase")
    ),
    responses(
        (status = 200, description = "Erasure complete"),
        (status = 412, description = "KMS_PROVIDER not configured"),
    ),
    security(("bearer_token" = []))
)]
pub fn gdpr_erase_handler() {}

#[utoipa::path(
    post,
    path = "/irl/admin/tokens",
    tag = "Admin",
    request_body = TokenIssueRequest,
    responses(
        (status = 200, description = "Token issued — save immediately, not stored server-side"),
    ),
    security(("bearer_token" = []))
)]
pub fn token_issue() {}

#[utoipa::path(
    delete,
    path = "/irl/admin/tokens/{token_id}",
    tag = "Admin",
    params(
        ("token_id" = uuid::Uuid, Path, description = "Token UUID to revoke")
    ),
    responses(
        (status = 200, description = "Token revoked"),
        (status = 404, description = "Token not found"),
    ),
    security(("bearer_token" = []))
)]
pub fn token_revoke() {}

// ── Supporting schema types ───────────────────────────────────────────────────

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct TraceListResponse {
    pub count: i64,
    pub traces: Vec<serde_json::Value>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub db_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_expiry_status: Option<String>,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct ShadowModeRequest {
    pub enabled: bool,
    pub reason: Option<String>,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct TokenIssueRequest {
    pub client_name: String,
}

// ── OpenAPI root document ─────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    info(
        title = "IRL Engine",
        version = "1.3.0",
        description = "Cryptographic pre-execution compliance gateway for AI trading agents. \
                       Seals reasoning traces with SHA-256 proof before orders reach the exchange.",
        license(name = "BSL 1.1", url = "https://mariadb.com/bsl11/"),
        contact(name = "IRL Engine", url = "https://github.com/GabrielGauss/irl-engine"),
    ),
    paths(
        authorize,
        bind_execution,
        get_trace,
        list_traces,
        health,
        get_pending,
        get_orphans,
        get_shadow_violations,
        get_attestation,
        list_anchors,
        shadow_mode_get,
        shadow_mode_set,
        audit_log_query,
        gdpr_erase_handler,
        token_issue,
        token_revoke,
    ),
    components(
        schemas(
            AuthorizeRequest,
            AuthorizeResponse,
            BindExecutionRequest,
            BindExecutionResult,
            VerificationStatus,
            ReasoningTrace,
            BiTemporalBlock,
            MtaBlock,
            AgentBlock,
            ExecutionBlock,
            HeartbeatBlock,
            PolicyBlock,
            IntegrityBlock,
            RegulatoryBlock,
            SignedHeartbeat,
            TraceListResponse,
            HealthResponse,
            ShadowModeRequest,
            TokenIssueRequest,
        )
    ),
    tags(
        (name = "Core", description = "Core IRL workflow: authorize → bind-execution"),
        (name = "Traces", description = "Trace inspection and filtering"),
        (name = "Operations", description = "Health, metrics, shadow violations"),
        (name = "Admin", description = "Owner-level admin — require owner token"),
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_token",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::Http::new(
                        utoipa::openapi::security::HttpAuthScheme::Bearer,
                    ),
                ),
            );
        }
    }
}
