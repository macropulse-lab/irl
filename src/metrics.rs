/// IRL Engine Prometheus metrics.
///
/// All metrics are registered with the default registry at module load time.
/// Expose via GET /metrics (Prometheus text exposition format).
///
/// The /metrics endpoint should be firewall-restricted in production —
/// it is unauthenticated by design to match the standard Prometheus scrape model.
use prometheus::{
    register_counter_vec, register_histogram, register_int_gauge_vec, CounterVec, Histogram,
    IntGaugeVec, TextEncoder,
};
use std::sync::OnceLock;

pub struct IrlMetrics {
    /// Total /irl/authorize calls by result label.
    /// result = "authorized" | "policy_blocked" | "shadow_blocked" | "error"
    pub authorize_total: CounterVec,

    /// /irl/authorize call latency in milliseconds.
    pub authorize_duration_ms: Histogram,

    /// Total /irl/bind-execution calls by verification status.
    /// status = "matched" | "divergent" | "orphan"
    pub bind_total: CounterVec,

    /// Policy blocks broken down by regime label and error code.
    pub policy_blocked_total: CounterVec,

    /// Active vs suspended agent count.
    /// status = "active" | "suspended"
    pub agent_count: IntGaugeVec,
}

static METRICS: OnceLock<IrlMetrics> = OnceLock::new();

pub fn get() -> &'static IrlMetrics {
    METRICS.get_or_init(|| IrlMetrics {
        authorize_total: register_counter_vec!(
            "irl_authorize_total",
            "Total /irl/authorize calls by result",
            &["result"]
        )
        .expect("failed to register irl_authorize_total"),

        authorize_duration_ms: register_histogram!(
            "irl_authorize_duration_ms",
            "Latency of /irl/authorize calls in milliseconds",
            vec![1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
        )
        .expect("failed to register irl_authorize_duration_ms"),

        bind_total: register_counter_vec!(
            "irl_bind_total",
            "Total /irl/bind-execution calls by verification status",
            &["status"]
        )
        .expect("failed to register irl_bind_total"),

        policy_blocked_total: register_counter_vec!(
            "irl_policy_blocked_total",
            "Policy blocks by regime label and error code",
            &["regime", "error_code"]
        )
        .expect("failed to register irl_policy_blocked_total"),

        agent_count: register_int_gauge_vec!(
            "irl_agent_count",
            "Registered agents by status",
            &["status"]
        )
        .expect("failed to register irl_agent_count"),
    })
}

/// Render all registered metrics in Prometheus text exposition format.
pub fn render() -> Result<String, String> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder
        .encode_to_string(&metric_families)
        .map_err(|e| e.to_string())
}
