use anyhow::{Context, Result};
use irl_engine::{
    build_router,
    config::{Config, MtaMode, TimeSource},
    heartbeat::HeartbeatValidator,
    kms, merkle,
    mta::{MacroPulseMtaClient, MockMtaClient, MtaClient, NullMtaClient},
    shadow_mode::ShadowModeCache,
    token_manager::TokenManager,
    verifier, webhook, AppState,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "irl_engine=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    let port = config.port;

    tracing::info!(
        "IRL Engine starting on port {port} \
         (run with 'backfill-encrypt' subcommand to encrypt existing plaintext traces)"
    );
    tracing::info!(
        "Layer 2: {}",
        if config.layer2_enabled {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    if config.shadow_mode {
        tracing::warn!(
            "SHADOW_MODE: policy violations will be logged but NOT blocked. \
             Set SHADOW_MODE=false to enable enforcement."
        );
    }
    if config.time_source == TimeSource::NtpSynced {
        tracing::warn!(
            "TIME_SOURCE=NtpSynced is a Phase-2 stub — currently falls back to system \
             clock. Roughtime attestation is NOT active. Set TIME_SOURCE=System to \
             suppress this warning."
        );
    }
    tracing::info!("Time source: {:?}", config.time_source);
    tracing::info!(
        "Trace expiry: {}s | Bind tolerance: {:.4}%",
        config.trace_expiry_ms / 1000,
        config.bind_size_tolerance * 100.0,
    );

    // Initialize asset alias map (symbol normalization across exchanges).
    // Format: ASSET_ALIAS_MAP=AAPL.USD|AAPL,BTCUSDT|BTC-PERP
    if let Ok(alias_map) = std::env::var("ASSET_ALIAS_MAP") {
        if !alias_map.trim().is_empty() {
            irl_engine::asset::init(&alias_map);
            tracing::info!("Asset alias map loaded from ASSET_ALIAS_MAP");
        }
    }

    let db_max_conn: u32 = std::env::var("DB_POOL_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let pool = PgPoolOptions::new()
        .max_connections(db_max_conn)
        .connect(&config.database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("Migrations applied");
    irl_engine::db::assert_trace_schema(&pool).await?;

    let key_provider = kms::build_key_provider(&config).await?;
    if key_provider.is_some() {
        tracing::info!("KMS: provider={:?} active", config.kms_provider);
    } else {
        tracing::warn!(
            "KMS: no provider configured — trace_json stored in plaintext (encryption_version=0). \
             Set KMS_PROVIDER=aws|vault|local to enable encryption."
        );
    }

    // ── Subcommand dispatch ────────────────────────────────────────────────────
    // Runs before HTTP server start so the pool is available but axum never binds.
    if let Some(cmd) = std::env::args().nth(1).as_deref() {
        match cmd {
            "backfill-encrypt" => {
                let kp = key_provider.ok_or_else(|| {
                    anyhow::anyhow!(
                        "KMS_PROVIDER must be set (aws|vault|local) to run backfill-encrypt. \
                         Plaintext rows cannot be encrypted without a key provider. \
                         Set KMS_PROVIDER and any required key env vars, then retry."
                    )
                })?;
                let provider_name = format!("{:?}", config.kms_provider).to_lowercase();
                let key_arn_or_path = config.kms_key_id.as_deref().unwrap_or("local");
                tracing::info!(
                    "backfill-encrypt: starting (provider={}, key={})",
                    provider_name,
                    key_arn_or_path
                );
                let count = irl_engine::backfill::run_backfill(
                    &pool,
                    kp.as_ref(),
                    &provider_name,
                    key_arn_or_path,
                )
                .await?;
                tracing::info!("backfill-encrypt complete: {} row(s) encrypted", count);
                return Ok(());
            }
            other => {
                anyhow::bail!(
                    "Unknown subcommand: '{}'. Known subcommands: backfill-encrypt",
                    other
                );
            }
        }
    }
    // ── End subcommand dispatch ───────────────────────────────────────────────

    // ── Shadow mode cache ─────────────────────────────────────────────────────
    // Load from irl.system_config; fall back to SHADOW_MODE env var if row absent.
    let shadow_cache = ShadowModeCache::new(pool.clone(), config.shadow_mode).await?;
    {
        let sc_refresh = shadow_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                if let Err(e) = sc_refresh.refresh().await {
                    tracing::warn!("Shadow mode cache refresh failed: {e}");
                }
            }
        });
    }

    let config = Arc::new(config);
    let heartbeat_validator = HeartbeatValidator::new(&config, &pool).await?;
    let mta_client: Arc<dyn MtaClient> = match config.mta_mode {
        MtaMode::Mock => {
            tracing::warn!("MTA_MODE=mock — using built-in mock MTA. NOT for production.");
            Arc::new(MockMtaClient)
        }
        MtaMode::External => {
            // T-2.1: spawn a background refresher so the MTA network fetch stays
            // off the /irl/authorize hot path (cache kept warm proactively).
            let client = Arc::new(MacroPulseMtaClient::new(&config));
            client.clone().spawn_refresh_worker();
            client
        }
        MtaMode::None => {
            tracing::info!("MTA: signal_mode=none — no external signal, agent caps only");
            Arc::new(NullMtaClient)
        }
    };

    // Warn if the default evaluation token is still in use.
    if config
        .irl_api_tokens
        .iter()
        .any(|t| t == "eval-token-change-me")
    {
        tracing::warn!(
            "SECURITY: IRL_API_TOKENS contains the default evaluation token. \
             Rotate it before exposing this instance to untrusted networks."
        );
    }

    // Initialize DB-backed token manager.
    // Syncs env tokens to irl.api_tokens table, loads active hashes into cache.
    let token_manager = TokenManager::new(pool.clone(), &config.irl_api_tokens).await?;
    tracing::info!(
        "Token manager ready — {} active token(s) loaded from DB",
        config.irl_api_tokens.len()
    );

    // Background task: refresh token cache every 60 s so revoked tokens take
    // effect without a restart.
    let tm_refresh = token_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(e) = tm_refresh.refresh_cache().await {
                tracing::warn!("Token cache refresh failed: {e}");
            }
        }
    });

    // Pre-compute TLS cert expiry for the health endpoint (MTLS-04).
    // If TLS is configured, load the server cert once here to extract not_after.
    // The TLS block below loads certs again to build the actual ServerConfig.
    let cert_expiry_not_after: Option<std::time::SystemTime> =
        if config.mtls_enabled || config.tls_cert_path.is_some() {
            use irl_engine::tls::generate_dev_certs;
            use x509_parser::prelude::{FromDer, X509Certificate};

            // Helper: extract first cert DER from PEM bytes.
            // Uses a scoped block so the BufRead borrow doesn't escape.
            fn first_cert_der_from_pem(pem: &[u8]) -> Option<Vec<u8>> {
                use rustls_pemfile::certs;
                let collected: Vec<_> = {
                    let mut rd = std::io::Cursor::new(pem);
                    certs(&mut rd).collect()
                };
                collected
                    .into_iter()
                    .next()
                    .and_then(|r| r.ok())
                    .map(|c| c.as_ref().to_vec())
            }

            let server_cert_der: Option<Vec<u8>> =
                if config.mtls_dev_certs || config.tls_cert_path.is_none() {
                    generate_dev_certs()
                        .ok()
                        .and_then(|dev| first_cert_der_from_pem(dev.server_cert_pem.as_bytes()))
                } else {
                    config
                        .tls_cert_path
                        .as_deref()
                        .and_then(|p| std::fs::read(p).ok())
                        .and_then(|pem| first_cert_der_from_pem(&pem))
                };

            server_cert_der.and_then(|der| {
                X509Certificate::from_der(&der)
                    .ok()
                    .map(|(_, cert)| cert.validity().not_after.to_datetime().into())
            })
        } else {
            None
        };

    // DB-02: optional read-replica pool for analytics SELECT routes
    let readonly_pool: Option<sqlx::PgPool> = if let Ok(ro_url) = std::env::var("DB_READONLY_URL") {
        let ro = sqlx::postgres::PgPoolOptions::new()
            .max_connections(db_max_conn)
            .connect(&ro_url)
            .await
            .context("Failed to connect to DB_READONLY_URL read replica")?;
        tracing::info!("DB_READONLY_URL: read-replica pool connected");
        Some(ro)
    } else {
        None
    };

    // DB-04: configure pg_partman retention from DB_RETENTION_MONTHS (default 36)
    let retention_months: i32 = std::env::var("DB_RETENTION_MONTHS")
        .unwrap_or_else(|_| "36".to_string())
        .parse()
        .context("DB_RETENTION_MONTHS must be a positive integer")?;

    sqlx::query(
        "UPDATE partman.part_config \
         SET retention              = ($1::text || ' months')::interval, \
             retention_keep_table   = false, \
             retention_keep_index   = false, \
             infinite_time_partitions = true, \
             premake                = 3 \
         WHERE parent_table = 'irl.reasoning_traces'",
    )
    .bind(retention_months)
    .execute(&pool)
    .await
    .context("Failed to configure pg_partman retention — is pg_partman installed?")?;

    let state = AppState {
        config: config.clone(),
        pool: pool.clone(),
        readonly_pool,
        heartbeat_validator,
        mta_client,
        key_provider,
        shadow_mode: shadow_cache,
        token_manager,
        cert_expiry_not_after,
    };

    // infinite_time_partitions = true (above): premake relative to now(), not to
    // the newest row. With false, a quiet period with no traces (Aug-Oct 2026,
    // while authorize was broken) stops premaking and new rows land in the
    // default partition.
    // DB-04: daily pg_partman maintenance — pre-create future partitions and drop old ones
    // pg_cron is preferred in production; this Tokio task is the application-side fallback.
    // To switch to pg_cron: SELECT cron.schedule('0 1 * * *', $$CALL partman.run_maintenance_proc(p_analyze := false)$$);
    let maintenance_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86_400));
        loop {
            interval.tick().await;
            // Function form, scoped to this table; the result used to be discarded,
            // which hid three months of missing partitions.
            match sqlx::query(
                "SELECT partman.run_maintenance(\
                 p_parent_table := 'irl.reasoning_traces', p_analyze := false)",
            )
            .execute(&maintenance_pool)
            .await
            {
                Ok(_) => tracing::info!("pg_partman maintenance ok"),
                Err(e) => tracing::error!(
                    error = %e,
                    "pg_partman maintenance failed; future partitions may be missing"
                ),
            }
        }
    });

    // Spawn the post-trade verifier expiry worker.
    let verifier_pool = Arc::new(pool.clone());
    let expiry_ms = config.trace_expiry_ms;
    tokio::spawn(verifier::run_expiry_worker(verifier_pool, expiry_ms));

    // Spawn the Merkle anchoring worker — daily tamper-evidence via OpenTimestamps.
    // merkle_v2_enabled selects domain-separated (RFC-6962) roots.
    tokio::spawn(merkle::run_merkle_anchor_worker(
        pool.clone(),
        config.merkle_v2_enabled,
    ));

    // Spawn the OTS upgrade worker — hourly retry for anchors whose initial OTS POST failed.
    tokio::spawn(merkle::run_ots_upgrade_worker(pool.clone()));

    // Spawn regime-change webhook worker (only when WEBHOOK_URL + WEBHOOK_SECRET are set).
    if let (Some(webhook_url), Some(webhook_secret)) =
        (config.webhook_url.clone(), config.webhook_secret.clone())
    {
        tracing::info!("Regime-change webhook worker starting (target: {webhook_url})");
        let wh_client = state.mta_client.clone();
        tokio::spawn(webhook::run_webhook_worker(
            wh_client,
            webhook_url,
            webhook_secret,
        ));
    }

    let app = build_router(state).layer(
        tower_http::trace::TraceLayer::new_for_http()
            .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO)),
    );

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

    if config.mtls_enabled || config.tls_cert_path.is_some() {
        use axum_server::tls_rustls::RustlsConfig;
        use irl_engine::tls::{build_server_config, generate_dev_certs};
        use rustls_pemfile::{certs as parse_certs, private_key as parse_key};
        use rustls_pki_types::CertificateDer;

        let (ca_der, cert_chain, key_der) = if config.mtls_dev_certs
            || config.tls_cert_path.is_none()
        {
            tracing::warn!(
                "MTLS: generating ephemeral dev certs (MTLS_DEV_CERTS=true or TLS_CERT_PATH unset). NOT for production."
            );
            let dev = generate_dev_certs()?;
            let ca_bytes = dev.ca_cert_pem.as_bytes().to_vec();
            let srv_bytes = dev.server_cert_pem.as_bytes().to_vec();
            let key_bytes = dev.server_key_pem.as_bytes().to_vec();
            let ca_certs: Vec<CertificateDer<'static>> =
                parse_certs(&mut ca_bytes.as_slice()).collect::<Result<Vec<_>, _>>()?;
            let server_certs: Vec<CertificateDer<'static>> =
                parse_certs(&mut srv_bytes.as_slice()).collect::<Result<Vec<_>, _>>()?;
            let key = parse_key(&mut key_bytes.as_slice())?
                .ok_or_else(|| anyhow::anyhow!("No private key in dev cert PEM"))?;
            (ca_certs[0].as_ref().to_vec(), server_certs, key)
        } else {
            let cert_path = config.tls_cert_path.as_deref().unwrap();
            let key_path = config.tls_key_path.as_deref().ok_or_else(|| {
                anyhow::anyhow!("TLS_KEY_PATH required when TLS_CERT_PATH is set")
            })?;
            let ca_path = config.tls_ca_cert_path.as_deref().ok_or_else(|| {
                anyhow::anyhow!("TLS_CA_CERT_PATH required when MTLS_ENABLED=true")
            })?;
            let cert_pem = std::fs::read(cert_path)?;
            let key_pem = std::fs::read(key_path)?;
            let ca_pem = std::fs::read(ca_path)?;
            let server_certs: Vec<CertificateDer<'static>> =
                parse_certs(&mut cert_pem.as_slice()).collect::<Result<Vec<_>, _>>()?;
            let key = parse_key(&mut key_pem.as_slice())?
                .ok_or_else(|| anyhow::anyhow!("No private key in {key_path}"))?;
            let ca_certs: Vec<CertificateDer<'static>> =
                parse_certs(&mut ca_pem.as_slice()).collect::<Result<Vec<_>, _>>()?;
            (ca_certs[0].as_ref().to_vec(), server_certs, key)
        };

        let server_config = build_server_config(
            &ca_der,
            cert_chain,
            key_der,
            config.mtls_enabled,
            config.mtls_required,
        )?;

        let tls_config = RustlsConfig::from_config(server_config);

        // Hot-reload watcher (MTLS-03): watch real cert files for changes.
        if !config.mtls_dev_certs && config.tls_cert_path.is_some() {
            use std::path::PathBuf;
            let cert_p = PathBuf::from(config.tls_cert_path.as_deref().unwrap());
            let key_p = PathBuf::from(config.tls_key_path.as_deref().unwrap_or(""));
            let watcher_config = tls_config.clone();
            tokio::spawn(irl_engine::tls::spawn_cert_watcher(
                watcher_config,
                cert_p,
                key_p,
            ));
            tracing::info!("TLS cert hot-reload watcher started");
        }

        // Expiry monitoring (MTLS-04): warn if cert expires within 14 days.
        if let Some(not_after) = cert_expiry_not_after {
            irl_engine::tls::spawn_expiry_warn_task(not_after);
        }

        tracing::info!(
            "Listening (TLS) on {addr} (mtls_enabled={}, mtls_required={})",
            config.mtls_enabled,
            config.mtls_required
        );
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("Listening (plain HTTP) on {addr}");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}
