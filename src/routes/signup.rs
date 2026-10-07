//! POST /irl/signup: self-serve, paper-tier client tokens.
//!
//! Anyone can get a token without asking an operator. Abuse is bounded by:
//! - tier 'paper': authorize only on paper venues (venue_id starting "paper"),
//!   and at most `SIGNUP_MAX_AGENTS` agents per token (default 3);
//! - at most `SIGNUP_PER_IP_PER_DAY` signups per requester IP (default 3);
//! - at most `SIGNUP_DAILY_CAP` signups per rolling 24 h overall (default 100);
//! - at most `SIGNUP_MAX_TRACES_PER_DAY` authorizations per paper token per
//!   rolling 24 h (default 500), and short identity fields, so a free token
//!   cannot fill the database;
//! - the usual per-token rate limit on every authenticated call.
//!
//! IPv6 requesters are keyed on their /64, so rotating addresses inside one
//! allocation does not multiply the per-IP allowance.
//!
//! Off unless `SIGNUP_ENABLED=true`, so a self-hosted engine never exposes it
//! by surprise. The requester IP is stored only as a SHA-256 hash.

use crate::audit::{self, AuditAction};
use crate::errors::AppError;
use crate::token_manager::sha256_hex;
use crate::AppState;
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rand::Rng;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

const MAX_CLIENT_NAME: usize = 64;
const MAX_CONTACT: usize = 200;

/// Signup limits, read from the environment on each request (cheap, and lets
/// an operator change them with a restart-free env reload in tests).
#[derive(Debug, Clone, Copy)]
pub struct SignupPolicy {
    pub enabled: bool,
    pub per_ip_per_day: i64,
    pub daily_cap: i64,
    pub max_agents: i64,
    pub max_traces_per_day: i64,
}

impl SignupPolicy {
    pub fn from_env() -> Self {
        fn num(key: &str, default: i64) -> i64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .filter(|n: &i64| *n >= 0)
                .unwrap_or(default)
        }
        Self {
            enabled: std::env::var("SIGNUP_ENABLED")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false),
            per_ip_per_day: num("SIGNUP_PER_IP_PER_DAY", 3),
            daily_cap: num("SIGNUP_DAILY_CAP", 100),
            max_agents: num("SIGNUP_MAX_AGENTS", 3),
            max_traces_per_day: num("SIGNUP_MAX_TRACES_PER_DAY", 500),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct SignupRequest {
    /// Optional label for the token (shown to the operator), e.g. "my-claude-trader".
    pub client_name: Option<String>,
    /// Optional way to reach you (email, X handle). Never required.
    pub contact: Option<String>,
}

/// The requester's IP. `X-Real-IP` is trusted only when the TCP peer is a
/// loopback or private address, i.e. the edge proxy; a direct caller cannot
/// spoof it to dodge the per-IP limit. No peer at all is not trusted.
pub fn requester_ip(headers: &HeaderMap, peer: Option<IpAddr>) -> Option<IpAddr> {
    let peer = peer.map(unmap);
    let from_proxy = match peer {
        None => false,
        Some(IpAddr::V4(v4)) => v4.is_loopback() || v4.is_private(),
        Some(IpAddr::V6(v6)) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    };
    let forwarded = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<IpAddr>().ok());
    if from_proxy {
        forwarded.map(unmap).or(peer)
    } else {
        peer
    }
}

/// `::ffff:a.b.c.d` (a dual-stack socket's view of an IPv4 peer) as IPv4.
fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// The per-IP limit key: the address for IPv4, the /64 for IPv6.
fn limit_key(ip: Option<IpAddr>) -> String {
    match ip {
        Some(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("v6:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Some(v4) => v4.to_string(),
        None => String::new(),
    }
}

fn clean(field: Option<String>, max: usize, name: &str) -> Result<Option<String>, AppError> {
    let Some(v) = field else { return Ok(None) };
    let v = v.trim().to_string();
    if v.is_empty() {
        return Ok(None);
    }
    if v.chars().count() > max || v.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!(
            "{name} must be at most {max} printable characters"
        )));
    }
    // A leading = + - @ turns into a formula if this is ever opened as CSV.
    if v.starts_with(['=', '+', '-', '@']) {
        return Err(AppError::BadRequest(format!(
            "{name} must not start with = + - or @"
        )));
    }
    Ok(Some(v))
}

pub async fn signup(
    State(state): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Option<Json<SignupRequest>>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let policy = SignupPolicy::from_env();
    if !policy.enabled {
        return Err(AppError::SignupDisabled);
    }
    let req = body.map(|Json(r)| r).unwrap_or_default();
    let client_name = clean(req.client_name, MAX_CLIENT_NAME, "client_name")?;
    let contact = clean(req.contact, MAX_CONTACT, "contact")?;

    let ip = requester_ip(&headers, connect.map(|c| c.0.ip()));
    let ip_hash = sha256_hex(&format!("irl-signup:{}", limit_key(ip)));

    let raw_bytes: [u8; 32] = rand::thread_rng().gen();
    let raw_token = hex::encode(raw_bytes);
    let hash = sha256_hex(&raw_token);
    let token_id = hash[..12].to_string();
    let client_name = client_name.unwrap_or_else(|| format!("signup-{}", &token_id[..6]));

    // Serialize signups so the two caps hold under concurrency.
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('irl-signup'))")
        .execute(&mut *tx)
        .await?;
    let (from_ip, total): (i64, i64) = sqlx::query_as(
        r#"
        SELECT count(*) FILTER (WHERE signup_ip_hash = $1), count(*)
        FROM irl.api_tokens
        WHERE source = 'signup' AND created_at > now() - interval '24 hours'
        "#,
    )
    .bind(&ip_hash)
    .fetch_one(&mut *tx)
    .await?;
    if from_ip >= policy.per_ip_per_day {
        return Err(AppError::QuotaExceeded(format!(
            "at most {} signups per day from one address; try again tomorrow",
            policy.per_ip_per_day
        )));
    }
    if total >= policy.daily_cap {
        return Err(AppError::QuotaExceeded(
            "today's signup capacity is used up; try again tomorrow".into(),
        ));
    }
    let (new_token_id,): (uuid::Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO irl.api_tokens
            (token_hash, client_name, source, status, role, tier, contact, signup_ip_hash)
        VALUES ($1, $2, 'signup', 'active', 'client', 'paper', $3, $4)
        RETURNING token_id
        "#,
    )
    .bind(&hash)
    .bind(&client_name)
    .bind(&contact)
    .bind(&ip_hash)
    .fetch_one(&mut *tx)
    .await?;
    // In the same transaction: a failure here must not leave a token that
    // was never shown to anyone counting against the caps.
    audit::insert_audit_log(
        &mut *tx,
        "signup",
        AuditAction::TokenIssue,
        Some(&token_id),
        Some(serde_json::json!({ "client_name": client_name, "tier": "paper" })),
        ip,
    )
    .await?;
    tx.commit().await?;

    // Make just this token usable at once (no full cache reload per signup).
    state.token_manager.insert_active(
        &hash,
        crate::token_manager::TokenInfo {
            token_id: new_token_id,
            is_owner: false,
            paper_only: true,
        },
    );

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "token": raw_token,
            "token_id": token_id,
            "client_name": client_name,
            "tier": "paper",
            "limits": {
                "venues": "paper only (venue_id starting with \"paper\")",
                "max_agents": policy.max_agents,
                "max_authorizations_per_day": policy.max_traces_per_day,
            },
            "next": "Register an agent: POST /irl/agents with this token as Bearer. \
                     Or run `uvx irl-gateway init`, which does both steps for you.",
            "note": "Store the token now; it is shown only once.",
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(ip: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert("x-real-ip", ip.parse().unwrap());
        m
    }

    #[test]
    fn ipv6_is_limited_per_64_and_mapped_v4_is_unwrapped() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        assert_eq!(limit_key(Some(a)), limit_key(Some(b)));
        let mapped: IpAddr = "::ffff:172.18.0.2".parse().unwrap();
        assert_eq!(
            requester_ip(&h("198.51.100.7"), Some(mapped)),
            Some("198.51.100.7".parse().unwrap()),
            "the edge seen through a dual-stack socket is still trusted"
        );
        assert_eq!(
            requester_ip(&h("198.51.100.7"), None),
            None,
            "no peer: not trusted"
        );
    }

    #[test]
    fn trusts_x_real_ip_only_from_a_private_peer() {
        let edge: IpAddr = "172.18.0.5".parse().unwrap();
        let outsider: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            requester_ip(&h("198.51.100.7"), Some(edge)),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(
            requester_ip(&h("198.51.100.7"), Some(outsider)),
            Some(outsider)
        );
        assert_eq!(requester_ip(&HeaderMap::new(), Some(edge)), Some(edge));
    }

    #[test]
    fn clean_rejects_long_or_control_input_and_drops_blank() {
        assert_eq!(clean(Some("  ".into()), 10, "x").unwrap(), None);
        assert_eq!(
            clean(Some(" bot ".into()), 10, "x").unwrap(),
            Some("bot".into())
        );
        assert!(clean(Some("a".repeat(11)), 10, "x").is_err());
        assert!(clean(Some("a\nb".into()), 10, "x").is_err());
        assert!(clean(Some("=HYPERLINK(1)".into()), 20, "x").is_err());
    }
}
