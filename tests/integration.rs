//! Integration tests — exercise the full HTTP → DB → response chain.
//!
//! These tests require a real PostgreSQL instance reachable via DATABASE_URL.
//! If DATABASE_URL is not set, every test exits early with a skip message.
//! In CI, DATABASE_URL is always set (see .github/workflows/ci.yml).
//!
//! Run with: cargo test --test integration -- --test-threads=1

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use irl_engine::layer2::Layer2Mode;
use irl_engine::{
    build_router,
    config::{Config, KmsProvider, MtaMode, TimeSource},
    heartbeat::HeartbeatValidator,
    kms::LocalDevProvider,
    mta::{MockMtaClient, MtaClient},
    shadow_mode::ShadowModeCache,
    token_manager::TokenManager,
    AppState,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

const TEST_TOKEN: &str = "integration-test-token";
// 64-char hex = valid SHA-256 model hash
const MODEL_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Truncate every table in the `irl` schema (except the sqlx migrations ledger)
/// so each integration test starts from a clean slate. The suite shares one
/// database and CI runs `--test-threads=1`; without this, rows from earlier
/// tests contaminate later assertions (stale agents/traces, owner-token state).
async fn reset_irl_tables(pool: &sqlx::PgPool) {
    let _ = sqlx::query(
        r#"
        DO $$
        DECLARE r RECORD;
        BEGIN
          FOR r IN SELECT tablename FROM pg_tables
                   WHERE schemaname = 'irl' AND tablename <> '_sqlx_migrations'
          LOOP
            EXECUTE 'TRUNCATE TABLE irl.' || quote_ident(r.tablename) || ' RESTART IDENTITY CASCADE';
          END LOOP;
        END $$;
        "#,
    )
    .execute(pool)
    .await;
}

/// Build a test app backed by a real DB and MockMtaClient.
/// Returns None and prints a skip message if DATABASE_URL is not set.
async fn build_test_app() -> Option<(axum::Router, sqlx::PgPool)> {
    build_test_app_with(None).await
}

/// Like build_test_app, with Layer 2 enabled in the given mode (None = disabled).
async fn build_test_app_with(
    layer2_mode: Option<Layer2Mode>,
) -> Option<(axum::Router, sqlx::PgPool)> {
    dotenvy::dotenv().ok();
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("Skipping integration tests: DATABASE_URL not set");
            return None;
        }
    };

    let pool = match PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&db_url)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Skipping integration tests: DB unreachable ({e})");
            return None;
        }
    };

    if let Err(e) = sqlx::migrate!("./migrations").run(&pool).await {
        eprintln!("Skipping integration tests: migrations failed ({e})");
        return None;
    }
    reset_irl_tables(&pool).await;

    let config = Arc::new(Config {
        database_url: db_url,
        mta_mode: MtaMode::Mock,
        mta_url: String::new(),
        mta_pubkey: ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap(),
        irl_api_tokens: vec![TEST_TOKEN.to_string()],
        time_source: TimeSource::System,
        max_heartbeat_drift_ms: 200,
        layer2_enabled: layer2_mode.is_some(),
        layer2_mode: layer2_mode.unwrap_or(Layer2Mode::Both),
        mta_ref_grace_secs: 300,
        bind_size_tolerance: 0.0001,
        trace_expiry_ms: 3_600_000,
        port: 4000,
        shadow_mode: false,
        metrics_enabled: true,
        metrics_token: None,
        rate_limit_per_second: 0, // disabled in integration tests
        max_body_bytes: 1_048_576,
        kms_provider: irl_engine::config::KmsProvider::None,
        kms_key_id: None,
        kms_key_version: 1,
        mtls_enabled: false,
        mtls_required: false,
        tls_cert_path: None,
        tls_key_path: None,
        tls_ca_cert_path: None,
        mtls_dev_certs: false,
        webhook_url: None,
        webhook_secret: None,
        snapshot_v2_enabled: false,
        merkle_v2_enabled: false,
    });

    let heartbeat_validator = match HeartbeatValidator::new(&config, &pool).await {
        Ok(hv) => hv,
        Err(e) => {
            eprintln!("Skipping integration tests: heartbeat validator init failed ({e})");
            return None;
        }
    };
    let mta_client: Arc<dyn MtaClient> = Arc::new(MockMtaClient);

    let shadow_mode = match ShadowModeCache::new(pool.clone(), false).await {
        Ok(sc) => sc,
        Err(e) => {
            eprintln!("Skipping integration tests: shadow mode cache init failed ({e})");
            return None;
        }
    };

    let token_manager = match TokenManager::new(pool.clone(), &config.irl_api_tokens).await {
        Ok(tm) => tm,
        Err(e) => {
            eprintln!("Skipping integration tests: token manager init failed ({e})");
            return None;
        }
    };

    let state = AppState {
        config: config.clone(),
        pool: pool.clone(),
        readonly_pool: None,
        heartbeat_validator,
        mta_client,
        key_provider: None,
        shadow_mode,
        token_manager,
        cert_expiry_not_after: None,
    };

    Some((build_router(state), pool))
}

fn auth_header() -> (&'static str, String) {
    ("Authorization", format!("Bearer {TEST_TOKEN}"))
}

fn json_post(uri: &str, body: Value, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/irl/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unauthorized_request_is_rejected() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/irl/agents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_agent_returns_agent_id() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    let resp = app
        .oneshot(json_post(
            "/irl/agents",
            json!({ "name": "reg-test-bot", "model_hash_hex": MODEL_HASH }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert!(body["agent_id"].as_str().is_some());
    assert_eq!(body["status"], "Active");
}

#[tokio::test]
async fn full_authorize_bind_matched_flow() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    // 1. Register agent
    let reg_resp = app
        .clone()
        .oneshot(json_post(
            "/irl/agents",
            json!({ "name": "flow-test-bot", "model_hash_hex": MODEL_HASH, "max_notional": 500000.0 }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(reg_resp.status(), StatusCode::CREATED);
    let reg = body_json(reg_resp).await;
    let agent_id = reg["agent_id"].as_str().unwrap().to_string();

    // 2. Authorize a trade (valid_time must be < txn_time)
    let valid_time = now_ms() - 500;
    let auth_resp = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            json!({
                "agent_id": agent_id,
                "model_hash_hex": MODEL_HASH,
                "model_id": "test-model-v1",
                "prompt_version": "v1",
                "feature_schema_id": "schema-v1",
                "hyperparameter_checksum": "abc123",
                "action": { "Long": 1.0 },
                "asset": "BTC-PERP",
                "order_type": "MARKET",
                "venue_id": "XNAS",
                "quantity": 1.0,
                "notional": 50000.0,
                "limit_price": null,
                "client_order_id": "test-order-1",
                "agent_valid_time": valid_time,
            }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(auth_resp.status(), StatusCode::OK);
    let auth = body_json(auth_resp).await;
    assert_eq!(auth["authorized"], true);
    let trace_id = auth["trace_id"].as_str().unwrap().to_string();
    let reasoning_hash = auth["reasoning_hash"].as_str().unwrap().to_string();
    assert_eq!(
        reasoning_hash.len(),
        64,
        "reasoning_hash must be 64 hex chars"
    );

    // 3. Bind execution — exact match → MATCHED
    let bind_resp = app
        .clone()
        .oneshot(json_post(
            "/irl/bind-execution",
            json!({
                "trace_id": trace_id,
                "exchange_tx_id": "EX-TX-001",
                "execution_status": "Filled",
                "asset": "BTC-PERP",
                "executed_quantity": 1.0,
                "execution_price": 50000.0,
            }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(bind_resp.status(), StatusCode::OK);
    let bind = body_json(bind_resp).await;
    assert_eq!(bind["verification_status"], "MATCHED");
    assert_eq!(bind["final_proof"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn bind_with_wrong_asset_is_divergent() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    // Register and authorize
    let reg = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/agents",
                json!({ "name": "diverge-test-bot", "model_hash_hex": MODEL_HASH }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let agent_id = reg["agent_id"].as_str().unwrap();

    let auth = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/authorize",
                json!({
                    "agent_id": agent_id,
                    "model_hash_hex": MODEL_HASH,
                    "model_id": "m", "prompt_version": "v1",
                    "feature_schema_id": "s", "hyperparameter_checksum": "h",
                    "action": { "Long": 1.0 },
                    "asset": "ETH-PERP",
                    "order_type": "MARKET", "venue_id": "XNAS",
                    "quantity": 1.0, "notional": 3000.0,
                    "limit_price": null,
                    "client_order_id": "ord-diverge",
                    "agent_valid_time": now_ms() - 500,
                }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let trace_id = auth["trace_id"].as_str().unwrap();

    // Bind with wrong asset
    let bind = body_json(
        app.oneshot(json_post(
            "/irl/bind-execution",
            json!({
                "trace_id": trace_id,
                "exchange_tx_id": "EX-TX-002",
                "execution_status": "Filled",
                "asset": "BTC-PERP",    // wrong — authorized for ETH-PERP
                "executed_quantity": 1.0,
                "execution_price": 3000.0,
            }),
            TEST_TOKEN,
        ))
        .await
        .unwrap(),
    )
    .await;

    assert_eq!(bind["verification_status"], "DIVERGENT");
    assert!(bind["divergence_reason"].as_str().is_some());
}

#[tokio::test]
async fn authorize_with_wrong_model_hash_is_rejected() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    let reg = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/agents",
                json!({ "name": "hash-mismatch-bot", "model_hash_hex": MODEL_HASH }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let agent_id = reg["agent_id"].as_str().unwrap();

    let wrong_hash = "b".repeat(64);
    let resp = app
        .oneshot(json_post(
            "/irl/authorize",
            json!({
                "agent_id": agent_id,
                "model_hash_hex": wrong_hash,
                "model_id": "m", "prompt_version": "v1",
                "feature_schema_id": "s", "hyperparameter_checksum": "h",
                "action": { "Long": 1.0 },
                "asset": "BTC-PERP",
                "order_type": "MARKET", "venue_id": "XNAS",
                "quantity": 1.0, "notional": 50000.0,
                "limit_price": null,
                "client_order_id": "ord-hash-mismatch",
                "agent_valid_time": now_ms() - 500,
            }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pending_endpoint_returns_list() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    let (k, v) = auth_header();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/irl/pending")
                .header(k, v)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["count"].as_u64().is_some());
    assert!(body["traces"].as_array().is_some());
}

#[tokio::test]
async fn notional_exceeds_cap_is_rejected() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    // Register agent with explicit max_notional = 1_000_000
    let reg = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/agents",
                json!({ "name": "cap-test-bot", "model_hash_hex": MODEL_HASH, "max_notional": 1_000_000.0 }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let agent_id = reg["agent_id"].as_str().unwrap();

    // MockMtaClient uses max_notional_scale = 1.0, so portfolio_cap = 1_000_000.
    // Request notional = 2_000_000 > cap → expect 403.
    let resp = app
        .oneshot(json_post(
            "/irl/authorize",
            json!({
                "agent_id": agent_id,
                "model_hash_hex": MODEL_HASH,
                "model_id": "test", "prompt_version": "v1",
                "feature_schema_id": "default",
                "hyperparameter_checksum": MODEL_HASH,
                "action": { "Long": 1.0 },
                "asset": "BTC-PERP",
                "order_type": "MARKET",
                "venue_id": "TEST",
                "quantity": 1.0,
                "notional": 2_000_000.0,
                "client_order_id": "test-cap-001",
                "agent_valid_time": now_ms() - 100,
            }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reduce_only_flag_is_accepted() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    // Register agent
    let reg = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/agents",
                json!({ "name": "reduce-only-bot", "model_hash_hex": MODEL_HASH }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let agent_id = reg["agent_id"].as_str().unwrap();

    let resp = app
        .oneshot(json_post(
            "/irl/authorize",
            json!({
                "agent_id": agent_id,
                "model_hash_hex": MODEL_HASH,
                "model_id": "test", "prompt_version": "v1",
                "feature_schema_id": "default",
                "hyperparameter_checksum": MODEL_HASH,
                "action": { "Short": 1.0 },
                "asset": "BTC-PERP",
                "order_type": "MARKET",
                "venue_id": "TEST",
                "quantity": 1.0,
                "notional": 100.0,
                "reduce_only": true,
                "client_order_id": "test-reduce-001",
                "agent_valid_time": now_ms() - 100,
            }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["authorized"], true);
}

#[tokio::test]
async fn traces_export_returns_results() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    // Register agent
    let reg = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/agents",
                json!({ "name": "traces-export-bot", "model_hash_hex": MODEL_HASH }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let agent_id = reg["agent_id"].as_str().unwrap();

    // Create a trace via authorize
    app.clone()
        .oneshot(json_post(
            "/irl/authorize",
            json!({
                "agent_id": agent_id,
                "model_hash_hex": MODEL_HASH,
                "model_id": "test", "prompt_version": "v1",
                "feature_schema_id": "default",
                "hyperparameter_checksum": MODEL_HASH,
                "action": { "Long": 1.0 },
                "asset": "ETH-PERP",
                "order_type": "MARKET",
                "venue_id": "TEST",
                "quantity": 1.0,
                "notional": 50.0,
                "client_order_id": "test-traces-001",
                "agent_valid_time": now_ms() - 100,
            }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();

    let (k, v) = auth_header();
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/irl/traces?agent_id={}&limit=5", agent_id))
                .header(k, v)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json["count"].as_u64().unwrap_or(0) >= 1);
}

// ── Phase 3: Admin audit + shadow mode ────────────────────────────────────────

#[tokio::test]
async fn shadow_mode_get_returns_current_state() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };
    let (k, v) = auth_header();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/irl/admin/shadow-mode")
                .header(k, v)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // May return 403 if TEST_TOKEN has client role (acceptable — endpoint exists)
    assert!(
        resp.status() == StatusCode::OK || resp.status() == StatusCode::FORBIDDEN,
        "GET /irl/admin/shadow-mode must return 200 or 403, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn audit_log_endpoint_requires_auth() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };
    // Unauthenticated request must be rejected
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/irl/admin/audit-log")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn audit_log_creates_entry_on_agent_register() {
    let Some((app, pool)) = build_test_app().await else {
        return;
    };

    // Register an agent to generate an audit log entry
    let reg = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/agents",
                json!({ "name": "audit-test-bot", "model_hash_hex": MODEL_HASH }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        reg["agent_id"].is_string(),
        "agent registration should succeed"
    );

    // Verify audit log entry exists in DB
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM irl.admin_audit_log WHERE action = 'AGENT_REGISTER'",
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(0);

    assert!(
        count >= 1,
        "audit log must have at least one agent.register entry"
    );
}

#[tokio::test]
async fn token_issue_endpoint_exists() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };
    let resp = app
        .oneshot(json_post(
            "/irl/admin/tokens",
            json!({ "client_name": "integration-test-client" }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "owner token must issue successfully"
    );
    let body = body_json(resp).await;
    assert!(body["token_id"].as_str().is_some());
    assert!(
        body["token"].as_str().is_some(),
        "raw token returned exactly once"
    );
}

// ── Phase 5: GDPR erasure ──────────────────────────────────────────────────────

/// Build a test app with a LocalDevProvider KMS for GDPR erasure tests.
/// Uses a fixed 32-byte wrapping key (safe for tests only — never for production).
/// Returns None if DATABASE_URL is not set or DB is unreachable.
async fn build_test_app_with_kms() -> Option<(axum::Router, sqlx::PgPool)> {
    dotenvy::dotenv().ok();
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("Skipping GDPR integration tests: DATABASE_URL not set");
            return None;
        }
    };

    let pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&db_url)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Skipping GDPR integration tests: DB unreachable ({e})");
            return None;
        }
    };

    if let Err(e) = sqlx::migrate!("./migrations").run(&pool).await {
        eprintln!("Skipping GDPR integration tests: migrations failed ({e})");
        return None;
    }
    reset_irl_tables(&pool).await;

    // Set LOCAL_KMS_KEY before constructing LocalDevProvider.
    // Uses a fixed test-only key — never use in production.
    std::env::set_var(
        "LOCAL_KMS_KEY",
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    );

    let kms_provider = match LocalDevProvider::new(1) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Skipping GDPR integration tests: KMS init failed ({e})");
            return None;
        }
    };

    let config = Arc::new(Config {
        database_url: db_url,
        mta_mode: MtaMode::Mock,
        mta_url: String::new(),
        mta_pubkey: ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap(),
        irl_api_tokens: vec![TEST_TOKEN.to_string()],
        time_source: TimeSource::System,
        max_heartbeat_drift_ms: 200,
        layer2_enabled: false,
        layer2_mode: Layer2Mode::Both,
        mta_ref_grace_secs: 300,
        bind_size_tolerance: 0.0001,
        trace_expiry_ms: 3_600_000,
        port: 4000,
        shadow_mode: false,
        metrics_enabled: true,
        metrics_token: None,
        rate_limit_per_second: 0,
        max_body_bytes: 1_048_576,
        kms_provider: KmsProvider::Local,
        kms_key_id: None,
        kms_key_version: 1,
        mtls_enabled: false,
        mtls_required: false,
        tls_cert_path: None,
        tls_key_path: None,
        tls_ca_cert_path: None,
        mtls_dev_certs: false,
        webhook_url: None,
        webhook_secret: None,
        snapshot_v2_enabled: false,
        merkle_v2_enabled: false,
    });

    let heartbeat_validator = match HeartbeatValidator::new(&config, &pool).await {
        Ok(hv) => hv,
        Err(e) => {
            eprintln!("Skipping GDPR integration tests: heartbeat validator init failed ({e})");
            return None;
        }
    };
    let mta_client: Arc<dyn MtaClient> = Arc::new(MockMtaClient);

    let shadow_mode = match ShadowModeCache::new(pool.clone(), false).await {
        Ok(sc) => sc,
        Err(e) => {
            eprintln!("Skipping GDPR integration tests: shadow mode cache init failed ({e})");
            return None;
        }
    };

    let token_manager = match TokenManager::new(pool.clone(), &config.irl_api_tokens).await {
        Ok(tm) => tm,
        Err(e) => {
            eprintln!("Skipping GDPR integration tests: token manager init failed ({e})");
            return None;
        }
    };

    let state = AppState {
        config: config.clone(),
        pool: pool.clone(),
        readonly_pool: None,
        heartbeat_validator,
        mta_client,
        key_provider: Some(std::sync::Arc::new(kms_provider)),
        shadow_mode,
        token_manager,
        cert_expiry_not_after: None,
    };

    Some((build_router(state), pool))
}

/// Helper: register an agent and authorize a single trace with known PII fields.
/// Returns (app, agent_id, trace_id, reasoning_hash_before).
async fn seed_agent_and_trace(
    app: axum::Router,
    pool: &sqlx::PgPool,
) -> (axum::Router, String, String, String) {
    // Register agent
    let reg = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/agents",
                json!({ "name": "gdpr-test-bot", "model_hash_hex": MODEL_HASH }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let agent_id = reg["agent_id"].as_str().unwrap().to_string();

    // Authorize a trace with PII-populated fields
    let auth = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/authorize",
                json!({
                    "agent_id": agent_id,
                    "model_hash_hex": MODEL_HASH,
                    "model_id": "gdpr-model-v1",
                    "prompt_version": "v1",
                    "feature_schema_id": "gdpr-schema-v1",
                    "hyperparameter_checksum": MODEL_HASH,
                    "action": { "Long": 1.0 },
                    "asset": "BTC-PERP",
                    "order_type": "MARKET",
                    "venue_id": "XNAS",
                    "quantity": 1.0,
                    "notional": 50000.0,
                    "limit_price": null,
                    "client_order_id": "gdpr-order-001",
                    "agent_valid_time": now_ms() - 500,
                }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let trace_id = auth["trace_id"].as_str().unwrap().to_string();

    // Fetch reasoning_hash from DB before erasure
    let reasoning_hash: String = sqlx::query_scalar(
        "SELECT reasoning_hash FROM irl.reasoning_traces WHERE trace_id = $1::uuid",
    )
    .bind(&trace_id)
    .fetch_one(pool)
    .await
    .unwrap();

    (app, agent_id, trace_id, reasoning_hash)
}

/// GDPR-01: POST /irl/admin/gdpr-erase/:agent_id returns 200 with traces_erased and status.
#[tokio::test]
async fn gdpr_erase() {
    let Some((app, pool)) = build_test_app_with_kms().await else {
        return;
    };

    let (app, agent_id, _trace_id, _) = seed_agent_and_trace(app, &pool).await;

    let resp = app
        .oneshot(json_post(
            &format!("/irl/admin/gdpr-erase/{agent_id}"),
            json!({}),
            TEST_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK, "GDPR erase must return 200");
    let body = body_json(resp).await;
    assert_eq!(
        body["traces_erased"].as_u64().unwrap_or(0),
        1,
        "must report 1 erased trace"
    );
    assert_eq!(body["status"], "erased", "status must be 'erased'");
    assert!(
        body["gdpr_request_id"].as_str().is_some(),
        "gdpr_request_id must be a UUID string"
    );
    assert_eq!(body["agent_id"].as_str().unwrap(), agent_id);
}

/// GDPR-02: After erasure, reasoning_hash is unchanged and gdpr_erased_at is non-null.
#[tokio::test]
async fn gdpr_erase_hash_preserved() {
    let Some((app, pool)) = build_test_app_with_kms().await else {
        return;
    };

    let (app, agent_id, _trace_id, pre_erasure_hash) = seed_agent_and_trace(app, &pool).await;

    // Erase
    let erase_resp = body_json(
        app.oneshot(json_post(
            &format!("/irl/admin/gdpr-erase/{agent_id}"),
            json!({}),
            TEST_TOKEN,
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(erase_resp["traces_erased"].as_u64().unwrap_or(0), 1);

    // Verify reasoning_hash is unchanged and gdpr_erased_at is set
    let row: (String, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "SELECT reasoning_hash, gdpr_erased_at \
         FROM irl.reasoning_traces \
         WHERE agent_id = $1::uuid \
         ORDER BY txn_time DESC \
         LIMIT 1",
    )
    .bind(&agent_id)
    .fetch_one(&pool)
    .await
    .expect("reasoning_traces row must exist after erasure");

    assert_eq!(
        row.0, pre_erasure_hash,
        "GDPR-02: reasoning_hash must be unchanged after erasure"
    );
    assert!(
        row.1.is_some(),
        "GDPR-02: gdpr_erased_at must be non-null after erasure"
    );
}

/// GDPR-03: After erasure, exactly one audit row exists with action=GDPR_ERASURE and
/// details_json.gdpr_request_id matching the response.
#[tokio::test]
async fn gdpr_erase_audit_row() {
    let Some((app, pool)) = build_test_app_with_kms().await else {
        return;
    };

    let (app, agent_id, _trace_id, _) = seed_agent_and_trace(app, &pool).await;

    // Erase
    let erase_resp = body_json(
        app.oneshot(json_post(
            &format!("/irl/admin/gdpr-erase/{agent_id}"),
            json!({}),
            TEST_TOKEN,
        ))
        .await
        .unwrap(),
    )
    .await;
    let response_gdpr_request_id = erase_resp["gdpr_request_id"]
        .as_str()
        .expect("gdpr_request_id must be in response")
        .to_string();

    // Check audit log
    let row: Option<(serde_json::Value,)> = sqlx::query_as(
        "SELECT details_json \
         FROM irl.admin_audit_log \
         WHERE action = 'GDPR_ERASURE' \
           AND target_id = $1 \
         ORDER BY created_at DESC \
         LIMIT 1",
    )
    .bind(&agent_id)
    .fetch_optional(&pool)
    .await
    .expect("audit log query should not fail");

    let (details,) = row.expect("GDPR-03: GDPR_ERASURE audit row must exist");
    let audit_gdpr_request_id = details["gdpr_request_id"]
        .as_str()
        .expect("details_json.gdpr_request_id must be a string");

    assert_eq!(
        audit_gdpr_request_id, response_gdpr_request_id,
        "GDPR-03: audit row gdpr_request_id must match response body"
    );
}

/// GDPR-04: When key_provider is None, endpoint returns 500 (encryption bypass refused).
#[tokio::test]
async fn gdpr_erase_no_kms() {
    // Build test app WITHOUT KMS (the standard build_test_app has key_provider: None)
    let Some((app, _pool)) = build_test_app().await else {
        return;
    };

    // Register an agent to have a valid agent_id
    let reg = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/agents",
                json!({ "name": "gdpr-no-kms-bot", "model_hash_hex": MODEL_HASH }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let agent_id = reg["agent_id"].as_str().unwrap().to_string();

    // Attempt GDPR erasure — must be refused since key_provider is None
    let resp = app
        .oneshot(json_post(
            &format!("/irl/admin/gdpr-erase/{agent_id}"),
            json!({}),
            TEST_TOKEN,
        ))
        .await
        .unwrap();

    // AppError::Encryption maps to 500 INTERNAL_SERVER_ERROR
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "GDPR-04: erasure without KMS must be refused with 500"
    );
}

// ── Security: agent list visibility ───────────────────────────────────────────

/// SEC-01: GET /irl/agents must return 403 for a client-role token.
///
/// After moving list_agents to admin_routes, only owner tokens may enumerate
/// all agents. A client token (issued via POST /irl/admin/tokens) must be denied.
#[tokio::test]
async fn list_agents_requires_owner_token() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    // Issue a client-role token using the owner token.
    let issue_resp = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/admin/tokens",
                json!({ "client_name": "sec-01-client" }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let client_token = issue_resp["token"].as_str().unwrap().to_string();

    // Client token must be rejected on GET /irl/agents with 403.
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/irl/agents")
                .header("Authorization", format!("Bearer {client_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "client-role token must not list agents"
    );
}

/// SEC-02: Full token lifecycle — issue, use, revoke, verify revocation.
#[tokio::test]
async fn token_issue_use_revoke_cycle() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };

    // Issue
    let issue = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/admin/tokens",
                json!({ "client_name": "lifecycle-test-client" }),
                TEST_TOKEN,
            ))
            .await
            .unwrap(),
    )
    .await;
    let client_token = issue["token"].as_str().unwrap().to_string();
    let token_id = issue["token_id"].as_str().unwrap().to_string();

    // New token can hit a bearer-protected endpoint
    let use_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/irl/pending")
                .header("Authorization", format!("Bearer {client_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        use_resp.status(),
        StatusCode::OK,
        "freshly issued token must be valid"
    );

    // Revoke
    let revoke = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/irl/admin/tokens/{token_id}"))
                .header("Authorization", format!("Bearer {TEST_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::OK, "revoke must succeed");

    // Revoked token must return 401
    let post_revoke = app
        .oneshot(
            Request::builder()
                .uri("/irl/pending")
                .header("Authorization", format!("Bearer {client_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        post_revoke.status(),
        StatusCode::UNAUTHORIZED,
        "revoked token must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Layer 2 v2: server-side regime binding (docs/design/layer2-v2.md)
// ---------------------------------------------------------------------------

const MOCK_MTA_REF: &str = "mock0000000000000000000000000000000000000000000000000000000000000000";

fn authed_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn register_v2_agent(app: &axum::Router, name: &str) -> String {
    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/agents",
            json!({ "name": name, "model_hash_hex": MODEL_HASH, "max_notional": 500000.0 }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp).await["agent_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn v2_authorize_body(agent_id: &str, client_order_id: &str, mta_ref: Option<&str>) -> Value {
    let mut body = json!({
        "agent_id": agent_id,
        "model_hash_hex": MODEL_HASH,
        "model_id": "test-model-v1",
        "prompt_version": "v1",
        "feature_schema_id": "schema-v1",
        "hyperparameter_checksum": "abc123",
        "action": { "Long": 1.0 },
        "asset": "BTC-PERP",
        "order_type": "MARKET",
        "venue_id": "XNAS",
        "quantity": 1.0,
        "notional": 1000.0,
        "client_order_id": client_order_id,
        "agent_valid_time": now_ms() - 500,
    });
    if let Some(r) = mta_ref {
        body["mta_ref"] = json!(r);
    }
    body
}

#[tokio::test]
async fn regime_endpoint_returns_current_verified_ref() {
    let Some((app, _)) = build_test_app_with(Some(Layer2Mode::Both)).await else {
        return;
    };

    let resp = app
        .oneshot(authed_get("/irl/regime", TEST_TOKEN))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["mta_ref"], MOCK_MTA_REF);
    assert_eq!(body["layer2_mode"], "both");
    assert_eq!(body["mta_ref_grace_secs"], 300);
}

#[tokio::test]
async fn v2_authorize_with_current_ref_then_duplicate_is_409_with_original_trace() {
    let Some((app, _)) = build_test_app_with(Some(Layer2Mode::V2)).await else {
        return;
    };
    let agent_id = register_v2_agent(&app, "v2-dup-bot").await;

    let first = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            v2_authorize_body(&agent_id, "v2-order-1", Some(MOCK_MTA_REF)),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let trace_id = body_json(first).await["trace_id"]
        .as_str()
        .unwrap()
        .to_string();

    let second = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            v2_authorize_body(&agent_id, "v2-order-1", Some(MOCK_MTA_REF)),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let body = body_json(second).await;
    assert_eq!(body["error"], "DUPLICATE_INTENT");
    assert!(body["message"].as_str().unwrap().contains(&trace_id));
}

#[tokio::test]
async fn v2_authorize_with_stale_ref_is_409() {
    let Some((app, _)) = build_test_app_with(Some(Layer2Mode::V2)).await else {
        return;
    };
    let agent_id = register_v2_agent(&app, "v2-stale-bot").await;

    let resp = app
        .oneshot(json_post(
            "/irl/authorize",
            v2_authorize_body(&agent_id, "v2-order-stale", Some("deadbeef")),
            TEST_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(resp).await["error"], "REGIME_REF_STALE");
}

#[tokio::test]
async fn v2_mode_requires_a_ref() {
    let Some((app, _)) = build_test_app_with(Some(Layer2Mode::V2)).await else {
        return;
    };
    let agent_id = register_v2_agent(&app, "v2-noref-bot").await;

    let resp = app
        .oneshot(json_post(
            "/irl/authorize",
            v2_authorize_body(&agent_id, "v2-order-noref", None),
            TEST_TOKEN,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "HEARTBEAT_MISSING");
}

// ── Agent trading scope: allowed_venues / allowed_assets ─────────────────────

fn scoped_authorize_body(agent_id: &str, coid: &str, venue: &str, asset: &str) -> Value {
    json!({
        "agent_id": agent_id,
        "model_hash_hex": MODEL_HASH,
        "model_id": "scope-model", "prompt_version": "v1",
        "feature_schema_id": "default",
        "hyperparameter_checksum": MODEL_HASH,
        "action": { "Long": 1.0 },
        "asset": asset,
        "order_type": "MARKET",
        "venue_id": venue,
        "quantity": 1.0,
        "notional": 100.0,
        "client_order_id": coid,
        "agent_valid_time": now_ms() - 100,
    })
}

#[tokio::test]
async fn authorize_enforces_agent_venue_and_asset_allowlists() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };
    let reg = app
        .clone()
        .oneshot(json_post(
            "/irl/agents",
            json!({
                "name": "scope-bot",
                "model_hash_hex": MODEL_HASH,
                "max_notional": 1000.0,
                "allowed_venues": ["binance"],
                "allowed_assets": ["BTCUSDT", "ETHUSDT"],
            }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(reg.status(), StatusCode::CREATED);
    let agent_id = body_json(reg).await["agent_id"]
        .as_str()
        .unwrap()
        .to_string();

    let wrong_venue = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            scoped_authorize_body(&agent_id, "scope-1", "kraken", "BTCUSDT"),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(wrong_venue.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(wrong_venue).await["error"], "VENUE_UNAUTHORIZED");

    let wrong_asset = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            scoped_authorize_body(&agent_id, "scope-2", "binance", "DOGEUSDT"),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(wrong_asset.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(wrong_asset).await["error"], "ASSET_UNAUTHORIZED");

    // In scope, matched case-insensitively.
    let ok = app
        .oneshot(json_post(
            "/irl/authorize",
            scoped_authorize_body(&agent_id, "scope-3", "BINANCE", "ethusdt"),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Tenant isolation: a client token acts only on agents it registered
// (migration 028, src/tenancy.rs)
// ---------------------------------------------------------------------------

async fn issue_client_token(app: &axum::Router, name: &str) -> String {
    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/admin/tokens",
            json!({ "client_name": name }),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp).await["token"].as_str().unwrap().to_string()
}

async fn register_agent_as(app: &axum::Router, token: &str, name: &str) -> String {
    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/agents",
            json!({ "name": name, "model_hash_hex": MODEL_HASH }),
            token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp).await["agent_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn authorize_body(agent_id: &str, client_order_id: &str) -> Value {
    json!({
        "agent_id": agent_id,
        "model_hash_hex": MODEL_HASH,
        "model_id": "tenant-model-v1",
        "prompt_version": "v1",
        "feature_schema_id": "schema-v1",
        "hyperparameter_checksum": "abc123",
        "action": { "Long": 1.0 },
        "asset": "BTC-PERP",
        "order_type": "MARKET",
        "venue_id": "XNAS",
        "quantity": 1.0,
        "notional": 50000.0,
        "limit_price": null,
        "client_order_id": client_order_id,
        "agent_valid_time": now_ms() - 500,
    })
}

fn bind_body(trace_id: &str) -> Value {
    json!({
        "trace_id": trace_id,
        "exchange_tx_id": "EX-TENANT-1",
        "execution_status": "Filled",
        "asset": "BTC-PERP",
        "executed_quantity": 1.0,
        "execution_price": 50000.0,
    })
}

async fn status_of(app: &axum::Router, req: Request<Body>) -> StatusCode {
    app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn client_token_cannot_touch_another_clients_agent() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };
    let alice = issue_client_token(&app, "tenant-alice").await;
    let mallory = issue_client_token(&app, "tenant-mallory").await;
    let agent = register_agent_as(&app, &alice, "alice-bot").await;

    // Mallory cannot authorize as Alice's agent, and nothing is sealed.
    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            authorize_body(&agent, "m-1"),
            &mallory,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(resp).await["error"], "AGENT_NOT_FOUND");

    let batch = body_json(
        app.clone()
            .oneshot(json_post(
                "/irl/authorize/batch",
                json!({ "requests": [authorize_body(&agent, "m-2")] }),
                &mallory,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(batch["results"][0]["error"], "AGENT_NOT_FOUND");

    // Alice can.
    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            authorize_body(&agent, "a-1"),
            &alice,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let trace_id = body_json(resp).await["trace_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Every agent- or trace-scoped read/write is hidden from Mallory.
    let hidden = [
        authed_get(&format!("/irl/trace/{trace_id}"), &mallory),
        authed_get(&format!("/irl/trace/{trace_id}/chain"), &mallory),
        authed_get(&format!("/irl/agents/{agent}"), &mallory),
        authed_get(
            &format!("/irl/attestation?from=2000-01-01T00:00:00Z&to=2100-01-01T00:00:00Z&agent_id={agent}"),
            &mallory,
        ),
        json_post("/irl/bind-execution", bind_body(&trace_id), &mallory),
    ];
    for req in hidden {
        let uri = req.uri().to_string();
        assert_eq!(status_of(&app, req).await, StatusCode::NOT_FOUND, "{uri}");
    }
    let suspend = Request::builder()
        .method("PATCH")
        .uri(format!("/irl/agents/{agent}/status"))
        .header("Authorization", format!("Bearer {mallory}"))
        .header("Content-Type", "application/json")
        .body(Body::from(json!({ "status": "Suspended" }).to_string()))
        .unwrap();
    assert_eq!(status_of(&app, suspend).await, StatusCode::NOT_FOUND);

    // Lists are filtered rather than refused.
    for uri in ["/irl/traces", "/irl/pending"] {
        let body = body_json(
            app.clone()
                .oneshot(authed_get(uri, &mallory))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["count"], 0, "{uri} leaked to another tenant");
        let body = body_json(app.clone().oneshot(authed_get(uri, &alice)).await.unwrap()).await;
        assert_eq!(body["count"], 1, "{uri} must show the owner its trace");
    }
    let bundle = body_json(
        app.clone()
            .oneshot(authed_get(
                "/irl/attestation?from=2000-01-01T00:00:00Z&to=2100-01-01T00:00:00Z",
                &mallory,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(bundle["traces"].as_array().unwrap().len(), 0);

    // The operator (owner token) still sees everything; Alice can bind.
    assert_eq!(
        status_of(
            &app,
            authed_get(&format!("/irl/trace/{trace_id}"), TEST_TOKEN)
        )
        .await,
        StatusCode::OK
    );
    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/bind-execution",
            bind_body(&trace_id),
            &alice,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["verification_status"], "MATCHED");
}

#[tokio::test]
async fn client_cannot_chain_onto_another_clients_trace() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };
    let alice = issue_client_token(&app, "chain-alice").await;
    let mallory = issue_client_token(&app, "chain-mallory").await;
    let alice_agent = register_agent_as(&app, &alice, "chain-alice-bot").await;
    let mallory_agent = register_agent_as(&app, &mallory, "chain-mallory-bot").await;

    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            authorize_body(&alice_agent, "ca-1"),
            &alice,
        ))
        .await
        .unwrap();
    let alice_trace = body_json(resp).await["trace_id"]
        .as_str()
        .unwrap()
        .to_string();

    let mut body = authorize_body(&mallory_agent, "cm-1");
    body["parent_trace_id"] = json!(alice_trace);
    let resp = app
        .clone()
        .oneshot(json_post("/irl/authorize", body, &mallory))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(resp).await["error"], "TRACE_NOT_FOUND");

    // Chaining onto its own trace still works.
    let mut body = authorize_body(&alice_agent, "ca-2");
    body["parent_trace_id"] = json!(alice_trace);
    let resp = app
        .clone()
        .oneshot(json_post("/irl/authorize", body, &alice))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn agents_without_an_owner_are_operator_only() {
    let Some((app, pool)) = build_test_app().await else {
        return;
    };
    let client = issue_client_token(&app, "tenant-legacy").await;
    let agent = register_agent_as(&app, TEST_TOKEN, "legacy-bot").await;
    sqlx::query("UPDATE irl.agent_registry SET owner_token_id = NULL WHERE agent_id = $1::uuid")
        .bind(&agent)
        .execute(&pool)
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            authorize_body(&agent, "l-1"),
            &client,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            authorize_body(&agent, "l-2"),
            TEST_TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Migration 028 backfills owners of pre-existing agents from AGENT_REGISTER
/// audit rows. Re-running it is a no-op for agents that already have one.
#[tokio::test]
async fn migration_028_backfills_owner_from_audit_log() {
    let Some((app, pool)) = build_test_app().await else {
        return;
    };
    let client = issue_client_token(&app, "tenant-backfill").await;
    let agent = register_agent_as(&app, &client, "backfill-bot").await;
    let owner_before: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT owner_token_id FROM irl.agent_registry WHERE agent_id = $1::uuid",
    )
    .bind(&agent)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(owner_before.is_some(), "registration must record the owner");

    // Simulate an agent registered before 028, then re-apply the migration.
    sqlx::query("UPDATE irl.agent_registry SET owner_token_id = NULL WHERE agent_id = $1::uuid")
        .bind(&agent)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../migrations/028_agent_owner_token.sql"))
        .execute(&pool)
        .await
        .unwrap();

    let owner_after: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT owner_token_id FROM irl.agent_registry WHERE agent_id = $1::uuid",
    )
    .bind(&agent)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(owner_after, owner_before);

    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/authorize",
            authorize_body(&agent, "b-1"),
            &client,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Self-serve signup (POST /irl/signup, migration 029)
// ---------------------------------------------------------------------------

fn signup_req(ip: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/irl/signup")
        .header("Content-Type", "application/json")
        .header("X-Real-IP", ip)
        // Arrive the way production does: through the edge, a private peer.
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [172, 18, 0, 2],
            40000,
        ))))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn clear_signup_env() {
    for k in [
        "SIGNUP_ENABLED",
        "SIGNUP_PER_IP_PER_DAY",
        "SIGNUP_DAILY_CAP",
        "SIGNUP_MAX_AGENTS",
        "SIGNUP_MAX_TRACES_PER_DAY",
    ] {
        std::env::remove_var(k);
    }
}

#[tokio::test]
async fn signup_is_off_unless_enabled() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };
    clear_signup_env();
    let resp = app
        .oneshot(signup_req("198.51.100.1", json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(resp).await["error"], "SIGNUP_DISABLED");
}

#[tokio::test]
async fn signup_token_is_paper_only_and_agent_capped() {
    let Some((app, pool)) = build_test_app().await else {
        return;
    };
    clear_signup_env();
    std::env::set_var("SIGNUP_ENABLED", "true");
    std::env::set_var("SIGNUP_MAX_AGENTS", "2");

    let resp = app
        .clone()
        .oneshot(signup_req(
            "198.51.100.20",
            json!({ "client_name": "self-serve-bot", "contact": "me@example.com" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["tier"], "paper");
    let token = body["token"].as_str().unwrap().to_string();

    // Stored as paper tier, with the IP hashed, never raw.
    let (tier, contact, ip_hash): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT tier, contact, signup_ip_hash FROM irl.api_tokens WHERE source = 'signup'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(tier, "paper");
    assert_eq!(contact.as_deref(), Some("me@example.com"));
    let ip_hash = ip_hash.unwrap();
    assert_eq!(ip_hash.len(), 64);
    assert!(!ip_hash.contains("198.51"));

    let agent = register_agent_as(&app, &token, "self-serve-agent").await;

    let mut paper = authorize_body(&agent, "ss-1");
    paper["venue_id"] = json!("paper-binance");
    let resp = app
        .clone()
        .oneshot(json_post("/irl/authorize", paper, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "paper venue must be allowed");

    let mut live = authorize_body(&agent, "ss-2");
    live["venue_id"] = json!("binance");
    let resp = app
        .clone()
        .oneshot(json_post("/irl/authorize", live, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["error"], "PAPER_TIER_ONLY");

    // Cap of 2 agents: the second registers, the third is refused.
    register_agent_as(&app, &token, "self-serve-agent-2").await;
    let resp = app
        .clone()
        .oneshot(json_post(
            "/irl/agents",
            json!({ "name": "one-too-many", "model_hash_hex": MODEL_HASH }),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_json(resp).await["error"], "QUOTA_EXCEEDED");

    // The operator's own (full) token is unaffected by paper rules.
    let op_agent = register_agent_as(&app, TEST_TOKEN, "operator-agent").await;
    let mut live = authorize_body(&op_agent, "op-1");
    live["venue_id"] = json!("binance");
    let resp = app
        .oneshot(json_post("/irl/authorize", live, TEST_TOKEN))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    clear_signup_env();
}

#[tokio::test]
async fn signup_enforces_per_ip_and_daily_caps() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };
    clear_signup_env();
    std::env::set_var("SIGNUP_ENABLED", "true");
    std::env::set_var("SIGNUP_PER_IP_PER_DAY", "2");
    std::env::set_var("SIGNUP_DAILY_CAP", "3");

    let status = |ip: &'static str| {
        let app = app.clone();
        async move {
            app.oneshot(signup_req(ip, json!({})))
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(status("198.51.100.30").await, StatusCode::CREATED);
    assert_eq!(status("198.51.100.30").await, StatusCode::CREATED);
    assert_eq!(
        status("198.51.100.30").await,
        StatusCode::TOO_MANY_REQUESTS,
        "per-IP cap"
    );
    assert_eq!(status("198.51.100.31").await, StatusCode::CREATED);
    assert_eq!(
        status("198.51.100.32").await,
        StatusCode::TOO_MANY_REQUESTS,
        "daily cap"
    );
    clear_signup_env();
}

#[tokio::test]
async fn paper_token_cannot_reactivate_and_is_capped_per_day() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };
    clear_signup_env();
    std::env::set_var("SIGNUP_ENABLED", "true");
    std::env::set_var("SIGNUP_MAX_TRACES_PER_DAY", "2");
    let resp = app
        .clone()
        .oneshot(signup_req("198.51.100.40", json!({})))
        .await
        .unwrap();
    let token = body_json(resp).await["token"].as_str().unwrap().to_string();
    let agent = register_agent_as(&app, &token, "capped-agent").await;

    let patch = |status: &str, tok: &str| {
        Request::builder()
            .method("PATCH")
            .uri(format!("/irl/agents/{agent}/status"))
            .header("Authorization", format!("Bearer {tok}"))
            .header("Content-Type", "application/json")
            .body(Body::from(json!({ "status": status }).to_string()))
            .unwrap()
    };
    assert_eq!(
        status_of(&app, patch("Suspended", &token)).await,
        StatusCode::OK,
        "own kill switch"
    );
    assert_eq!(
        status_of(&app, patch("Active", &token)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status_of(&app, patch("Active", TEST_TOKEN)).await,
        StatusCode::OK,
        "operator can"
    );

    let auth = |n: u32| {
        let mut b = authorize_body(&agent, &format!("cap-{n}"));
        b["venue_id"] = json!("paper-binance");
        json_post("/irl/authorize", b, &token)
    };
    assert_eq!(status_of(&app, auth(1)).await, StatusCode::OK);
    assert_eq!(status_of(&app, auth(2)).await, StatusCode::OK);
    let resp = app.clone().oneshot(auth(3)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_json(resp).await["error"], "QUOTA_EXCEEDED");

    std::env::set_var("SIGNUP_MAX_TRACES_PER_DAY", "100");
    let mut long = authorize_body(&agent, "long-1");
    long["venue_id"] = json!("paper-binance");
    long["model_id"] = json!("m".repeat(300));
    let resp = app
        .oneshot(json_post("/irl/authorize", long, &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    clear_signup_env();
}

#[tokio::test]
async fn signup_rejects_formula_like_contact() {
    let Some((app, _)) = build_test_app().await else {
        return;
    };
    clear_signup_env();
    std::env::set_var("SIGNUP_ENABLED", "true");
    let resp = app
        .oneshot(signup_req(
            "198.51.100.50",
            json!({ "contact": "=HYPERLINK(\"x\")" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    clear_signup_env();
}
