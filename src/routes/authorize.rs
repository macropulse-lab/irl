use crate::auth::Caller;
use crate::db;
use crate::errors::AppError;
use crate::heartbeat::SignedHeartbeat;
use crate::metrics;
use crate::middleware::client_cert::ClientCertInfo;
use crate::policy;
use crate::registry;
use crate::seal;
use crate::snapshot::{
    self, AgentBlock, AuthorizeRequest, BiTemporalBlock, CognitiveSnapshot, ExecutionBlock,
    ExecutionIntent, HeartbeatBlock, IntegrityBlock, MtaBlock, PolicyBlock, ReasoningTrace,
    RegulatoryBlock, TradeAction,
};
use crate::time::now_ms;
use crate::AppState;
use axum::{extract::State, Extension, Json};
use chrono::{TimeZone, Utc};
use serde_json::json;
use uuid::Uuid;

/// POST /irl/authorize
///
/// The core IRL endpoint. Thin wrapper around `authorize_one` that handles
/// axum extraction and JSON wrapping.
///
/// On policy violation: returns 403 REGIME_VIOLATION with full context.
/// The HALTED trace is still persisted — the audit log must record all attempts.
pub async fn authorize(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    cert_ext: Option<Extension<ClientCertInfo>>,
    Json(req): Json<AuthorizeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let cert_info = cert_ext.map(|e| e.0);
    authorize_one(&state, &caller, cert_info.as_ref(), req)
        .await
        .map(Json)
}

/// Core authorization logic called by both the single and batch endpoints.
pub async fn authorize_one(
    state: &AppState,
    caller: &Caller,
    cert_info: Option<&ClientCertInfo>,
    req: AuthorizeRequest,
) -> Result<serde_json::Value, AppError> {
    let start = std::time::Instant::now();
    let cfg = &state.config;

    // Tenant isolation: a client token may only authorize its own agents.
    // Checked before anything is sealed, so no trace is written for others.
    crate::tenancy::ensure_agent(&state.pool, caller, req.agent_id).await?;
    // ...and may only chain onto its own traces, so it cannot graft itself
    // into another tenant's lineage.
    if let Some(parent) = req.parent_trace_id {
        crate::tenancy::ensure_trace(&state.pool, caller, parent).await?;
    }

    // --- MTLS-02: Client Cert CN Validation ---
    // If a client cert was presented (mTLS active), CN must match the agent_id.
    // When MTLS_ENABLED=false or client sent no cert, cert_info is None — skip.
    if let Some(ci) = cert_info {
        if ci.cn != req.agent_id.to_string() {
            tracing::warn!(
                "mTLS CN mismatch: cert CN='{}' != agent_id='{}'",
                ci.cn,
                req.agent_id
            );
            return Err(AppError::Forbidden);
        }
    }

    // --- Layer 2: regime binding (legacy heartbeat or v2 regime ref) ---
    let l2_path = crate::layer2::select_path(
        cfg.layer2_enabled,
        cfg.layer2_mode,
        req.mta_ref.as_deref(),
        req.heartbeat.is_some(),
    )
    .map_err(AppError::Heartbeat)?;

    let mut heartbeat = req.heartbeat.clone().unwrap_or(SignedHeartbeat {
        sequence_id: 0,
        timestamp_ms: req.agent_valid_time as u64,
        regime_id: 0,
        mta_ref: String::new(),
        signature: vec![],
    });

    let drift_ms = if l2_path == crate::layer2::L2Path::Heartbeat {
        state
            .heartbeat_validator
            .validate(&heartbeat, req.agent_id, cfg, Some(&state.pool))
            .await?
    } else {
        0
    };

    // --- MTA: Fetch and verify the Market Truth Anchor ---
    let mta = state.mta_client.fetch_verified().await?;

    match &l2_path {
        crate::layer2::L2Path::Heartbeat => {
            // --- L2-01: Bind heartbeat.mta_ref to current MTA hash ---
            // Prevents an agent from presenting a valid heartbeat signed against a stale
            // MTA broadcast that references a different (possibly softer) regime.
            // Empty mta_ref is allowed for legacy Layer 1 agents during the migration window.
            if !heartbeat.mta_ref.is_empty() && heartbeat.mta_ref != mta.hash {
                return Err(AppError::Heartbeat(
                    crate::errors::HeartbeatError::MtaRefMismatch {
                        got: heartbeat.mta_ref.clone(),
                        expected: mta.hash.clone(),
                    },
                ));
            }
        }
        crate::layer2::L2Path::RegimeRef(given) => {
            // --- Layer 2 v2: the agent's regime ref must be IRL's own verified
            // current ref, or the one it replaced within the grace window.
            let previous = state.mta_client.previous_ref();
            let accepted = crate::layer2::ref_accepted(
                given,
                &mta.hash,
                previous.as_ref().map(|(r, at)| (r.as_str(), *at)),
                crate::mta::unix_ms_now(),
                cfg.mta_ref_grace_secs,
            );
            if !accepted {
                return Err(AppError::Heartbeat(
                    crate::errors::HeartbeatError::RegimeRefStale {
                        got: given.clone(),
                        current: mta.hash.clone(),
                    },
                ));
            }
            // Recorded in the trace's heartbeat block for audit.
            heartbeat.mta_ref = given.clone();
        }
        crate::layer2::L2Path::Off => {}
    }

    // --- Multi-Agent Registry: Verify agent identity ---
    // Decode the agent-supplied model hash (hex → bytes).
    let model_hash_bytes = hex::decode(&req.model_hash_hex)
        .map_err(|_| AppError::Policy(crate::errors::PolicyError::ModelHashMismatch))?;
    let model_hash: [u8; 32] = model_hash_bytes
        .try_into()
        .map_err(|_| AppError::Policy(crate::errors::PolicyError::ModelHashMismatch))?;

    // Build ExecutionIntent first (needed for MAR notional check).
    // Long/Short carry quantity in their variant for legacy clients; Custom and Neutral do not.
    let action = match req.action {
        TradeAction::Long(_) => TradeAction::Long(req.quantity),
        TradeAction::Short(_) => TradeAction::Short(req.quantity),
        TradeAction::Neutral => TradeAction::Neutral,
        TradeAction::Custom(ref s) => TradeAction::Custom(s.clone()),
    };

    let intent = ExecutionIntent {
        action: action.clone(),
        asset: req.asset.clone(),
        order_type: req.order_type.clone(),
        venue_id: req.venue_id.clone(),
        quantity: req.quantity,
        notional: req.notional,
        notional_currency: req.notional_currency.clone(),
        multiplier: req.multiplier,
        limit_price: req.limit_price,
        stop_price: req.stop_price,
        client_order_id: req.client_order_id.clone(),
    };

    let agent_profile = registry::authorize_agent(
        &state.pool,
        req.agent_id,
        &model_hash,
        mta.regime_id,
        &mta.pubkey_fingerprint,
        &req.venue_id,
        &req.asset,
    )
    .await?;

    // --- Bitemporal Seal ---
    let txn_time = now_ms(cfg);

    let latent_fingerprint = snapshot::compute_latent_fingerprint(
        &req.model_id,
        &req.prompt_version,
        &req.feature_schema_id,
        &req.hyperparameter_checksum,
    );

    let snap = CognitiveSnapshot {
        trace_id: Uuid::new_v4(),
        mta_regime_id: mta.regime_id,
        mta_version: mta.version.clone(),
        mta_hash: mta.hash.clone(),
        latent_fingerprint: latent_fingerprint.clone(),
        feature_schema_id: req.feature_schema_id.clone(),
        execution: intent.clone(),
        valid_time: req.agent_valid_time,
        txn_time,
        heartbeat: heartbeat.clone(),
    };

    seal::verify_bitemporal(&snap)?;

    // --- Reasoning-hash seal (v1 legacy, or v2 split-commitment behind a flag) ---
    // v2 seals over the public field group plus a commitment to the private
    // fields, letting an auditor recompute the hash offline from the public
    // bundle without seeing private order detail. Default off — enabling
    // requires the v2-aware verifier. Measured cost ~2µs; safe on the hot path.
    let (reasoning_hash, snapshot_version, private_commitment): (String, i16, Option<String>) =
        if cfg.snapshot_v2_enabled {
            (
                crate::seal_v2::seal_v2(&snap)?,
                crate::seal_v2::SNAPSHOT_VERSION_V2,
                Some(crate::seal_v2::private_commitment(&snap)),
            )
        } else {
            (seal::seal(&snap)?, 1, None)
        };

    // --- Policy Enforcement (Kill-Switch) ---
    // Checks: allowed_sides (direction) + notional <= agent_cap × mta.max_notional_scale.
    let m = metrics::get();

    let (decision, shadow_blocked) = match policy::enforce(
        &mta,
        &action,
        req.notional,
        agent_profile.max_notional,
        req.reduce_only,
    ) {
        Ok(d) => (d, false),
        Err(e) => {
            if state.shadow_mode.is_enabled() {
                // Shadow mode: log the violation but do not block the agent.
                // Persist with SHADOW_HALTED so compliance can review without
                // disrupting live trading.
                tracing::warn!(
                    trace_id = %snap.trace_id,
                    error = %e,
                    "SHADOW_MODE: policy violation would have blocked this trade"
                );
                let error_code = e.error_code();
                m.policy_blocked_total
                    .with_label_values(&[&mta.regime_label, error_code])
                    .inc();
                let mut shadow_decision = policy::evaluate(
                    &mta,
                    &action,
                    req.notional,
                    agent_profile.max_notional,
                    req.reduce_only,
                );
                shadow_decision.result = policy::PolicyResult::ShadowHalted;
                (shadow_decision, true)
            } else {
                // Enforcement active: persist the HALTED trace then return 403.
                let error_code = e.error_code();
                m.policy_blocked_total
                    .with_label_values(&[&mta.regime_label, error_code])
                    .inc();
                let halted_decision = policy::evaluate(
                    &mta,
                    &action,
                    req.notional,
                    agent_profile.max_notional,
                    req.reduce_only,
                );
                let trace = build_trace(
                    &snap,
                    &mta,
                    drift_ms,
                    &halted_decision,
                    &reasoning_hash,
                    cfg,
                    req.agent_id,
                    req.regulatory.clone(),
                );
                let _ = db::insert_trace(
                    &state.pool,
                    &snap,
                    &reasoning_hash,
                    &halted_decision,
                    &trace,
                    Some(req.agent_id),
                    state.key_provider.as_deref(),
                    Some(mta.pubkey_fingerprint.as_str()),
                    req.parent_trace_id,
                    snapshot_version,
                    private_commitment.as_deref(),
                )
                .await;
                m.authorize_total
                    .with_label_values(&["policy_blocked"])
                    .inc();
                m.authorize_duration_ms
                    .observe(start.elapsed().as_secs_f64() * 1000.0);
                return Err(e);
            }
        }
    };

    let trace = build_trace(
        &snap,
        &mta,
        drift_ms,
        &decision,
        &reasoning_hash,
        cfg,
        req.agent_id,
        req.regulatory,
    );

    // Portfolio check is enforced atomically (with an advisory lock) only for
    // genuinely authorized, non-reduce_only trades.
    // - reduce_only: closing a position reduces exposure — skip the cap check.
    // - shadow_blocked: trade is already flagged as SHADOW_HALTED — no cap consumption.
    let portfolio_check = if !req.reduce_only && !shadow_blocked {
        let cap = agent_profile.max_notional * mta.max_notional_scale;
        Some((cap, mta.regime_label.clone()))
    } else {
        None
    };

    // --- Layer 2 v2: replay protection and idempotent retries ---
    // One intent per (agent_id, client_order_id); a resubmission gets 409 with
    // the original trace_id. Claimed just before the insert and released if
    // the insert fails (e.g. portfolio cap), so a failed attempt can be retried.
    let claimed_intent = if matches!(l2_path, crate::layer2::L2Path::RegimeRef(_)) {
        match db::claim_intent(
            &state.pool,
            req.agent_id,
            &req.client_order_id,
            snap.trace_id,
        )
        .await?
        {
            db::IntentClaim::Claimed => true,
            db::IntentClaim::Duplicate(existing) => {
                return Err(AppError::DuplicateIntent(existing.to_string()))
            }
        }
    } else {
        false
    };

    if let Err(insert_err) = db::insert_trace_atomic(
        &state.pool,
        &snap,
        &reasoning_hash,
        &decision,
        &trace,
        Some(req.agent_id),
        portfolio_check,
        state.key_provider.as_deref(),
        Some(mta.pubkey_fingerprint.as_str()),
        req.parent_trace_id,
        snapshot_version,
        private_commitment.as_deref(),
    )
    .await
    {
        if claimed_intent {
            if let Err(release_err) = db::release_intent(
                &state.pool,
                req.agent_id,
                &req.client_order_id,
                snap.trace_id,
            )
            .await
            {
                tracing::error!(
                    error = %release_err,
                    "failed to release intent key after trace insert failure"
                );
            }
        }
        return Err(insert_err);
    }

    let result_label = if shadow_blocked {
        "shadow_blocked"
    } else {
        "authorized"
    };
    m.authorize_total.with_label_values(&[result_label]).inc();
    m.authorize_duration_ms
        .observe(start.elapsed().as_secs_f64() * 1000.0);

    Ok(json!({
        "trace_id": snap.trace_id,
        "reasoning_hash": reasoning_hash,
        "authorized": true,
        "shadow_blocked": shadow_blocked,
    }))
}

#[allow(clippy::too_many_arguments)]
fn build_trace(
    snap: &CognitiveSnapshot,
    mta: &crate::mta::MtaState,
    drift_ms: i64,
    decision: &policy::PolicyDecision,
    reasoning_hash: &str,
    cfg: &crate::config::Config,
    agent_id: Uuid,
    regulatory: Option<RegulatoryBlock>,
) -> ReasoningTrace {
    ReasoningTrace {
        trace_id: snap.trace_id,
        version: "1.0.0",
        bitemporal: BiTemporalBlock {
            valid_time: Utc
                .timestamp_millis_opt(snap.valid_time)
                .single()
                .unwrap_or_default(),
            txn_time: Utc
                .timestamp_millis_opt(snap.txn_time)
                .single()
                .unwrap_or_default(),
            time_source: format!("{:?}", cfg.time_source),
        },
        mta: MtaBlock {
            regime_id: mta.regime_id,
            regime_label: mta.regime_label.clone(),
            risk_level: mta.risk_level,
            max_notional_scale: mta.max_notional_scale,
            allowed_sides: mta.allowed_sides.clone(),
            version: mta.version.clone(),
            hash: mta.hash.clone(),
            signature_valid: true,
        },
        agent: AgentBlock {
            agent_id,
            latent_fingerprint: snap.latent_fingerprint.clone(),
            feature_schema_id: snap.feature_schema_id.clone(),
        },
        execution: ExecutionBlock {
            action: snap.execution.action.to_string(),
            asset: snap.execution.asset.clone(),
            order_type: snap.execution.order_type.to_string(),
            venue_id: snap.execution.venue_id.clone(),
            quantity: snap.execution.quantity,
            notional: snap.execution.notional,
            notional_currency: snap.execution.notional_currency.clone(),
            multiplier: snap.execution.multiplier,
            limit_price: snap.execution.limit_price,
            stop_price: snap.execution.stop_price,
            client_order_id: snap.execution.client_order_id.clone(),
        },
        heartbeat: HeartbeatBlock {
            sequence_id: snap.heartbeat.sequence_id,
            signature_valid: true,
            drift_ms,
        },
        policy: PolicyBlock {
            id: decision.policy_id.clone(),
            version: decision.policy_version.clone(),
            hash: decision.policy_hash.clone(),
            result: decision.result.to_string(),
        },
        integrity: IntegrityBlock {
            reasoning_hash: reasoning_hash.to_string(),
            final_proof: None,
            verification_status: "PENDING".to_string(),
            execution_status: None,
        },
        regulatory,
    }
}
