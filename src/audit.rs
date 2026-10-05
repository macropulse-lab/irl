//! Audit log helper.
//!
//! Provides `AuditAction` enum and `insert_audit_log()` for writing append-only
//! rows to `irl.admin_audit_log` (created in migration 012).
//!
//! ip_address is accepted as `Option<std::net::IpAddr>` and converted to a
//! String before binding — sqlx 0.7 has no built-in INET encoder, but PostgreSQL
//! accepts text literals for INET columns via implicit cast.

use crate::errors::AppError;
use sqlx::PgPool;

/// All operator actions that must appear in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    AgentRegister,
    AgentSuspend,
    AgentActivate,
    AgentStatusChange,
    TokenIssue,
    TokenRevoke,
    ShadowModeChange,
    GdprErasure,
}

impl AuditAction {
    /// Returns the canonical uppercase string stored in `irl.admin_audit_log.action`.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::AgentRegister => "AGENT_REGISTER",
            AuditAction::AgentSuspend => "AGENT_SUSPEND",
            AuditAction::AgentActivate => "AGENT_ACTIVATE",
            AuditAction::AgentStatusChange => "AGENT_STATUS_CHANGE",
            AuditAction::TokenIssue => "TOKEN_ISSUE",
            AuditAction::TokenRevoke => "TOKEN_REVOKE",
            AuditAction::ShadowModeChange => "SHADOW_MODE_CHANGE",
            AuditAction::GdprErasure => "GDPR_ERASURE",
        }
    }

    /// Returns the canonical uppercase string stored in `irl.admin_audit_log.target_type`.
    pub fn target_type(&self) -> &'static str {
        match self {
            AuditAction::AgentRegister
            | AuditAction::AgentSuspend
            | AuditAction::AgentActivate
            | AuditAction::AgentStatusChange
            | AuditAction::GdprErasure => "AGENT",
            AuditAction::TokenIssue | AuditAction::TokenRevoke => "TOKEN",
            AuditAction::ShadowModeChange => "SHADOW_MODE",
        }
    }
}

/// Insert one row into `irl.admin_audit_log`.
///
/// Parameters:
/// - `operator_id` — who performed the action (token id, user id, or "system")
/// - `action` — the `AuditAction` variant
/// - `target_id` — optional UUID or identifier of the affected resource
/// - `details_json` — optional structured payload (old/new values, reason, etc.)
/// - `ip_address` — source IP of the operator request; bound as text so
///   PostgreSQL's implicit text→INET cast handles the column type
pub async fn insert_audit_log(
    pool: &PgPool,
    operator_id: &str,
    action: AuditAction,
    target_id: Option<&str>,
    details_json: Option<serde_json::Value>,
    ip_address: Option<std::net::IpAddr>,
) -> Result<(), AppError> {
    let ip_str = ip_address.map(|ip| ip.to_string());

    sqlx::query(
        r#"
        INSERT INTO irl.admin_audit_log
            (operator_id, action, target_type, target_id, details_json, ip_address)
        VALUES ($1, $2, $3, $4, $5, $6::inet)
        "#,
    )
    .bind(operator_id)
    .bind(action.as_str())
    .bind(action.target_type())
    .bind(target_id)
    .bind(details_json)
    .bind(ip_str.as_deref())
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_action_as_str() {
        assert_eq!(AuditAction::AgentRegister.as_str(), "AGENT_REGISTER");
        assert_eq!(AuditAction::AgentSuspend.as_str(), "AGENT_SUSPEND");
        assert_eq!(AuditAction::AgentActivate.as_str(), "AGENT_ACTIVATE");
        assert_eq!(
            AuditAction::AgentStatusChange.as_str(),
            "AGENT_STATUS_CHANGE"
        );
        assert_eq!(AuditAction::TokenIssue.as_str(), "TOKEN_ISSUE");
        assert_eq!(AuditAction::TokenRevoke.as_str(), "TOKEN_REVOKE");
        assert_eq!(AuditAction::ShadowModeChange.as_str(), "SHADOW_MODE_CHANGE");
        assert_eq!(AuditAction::GdprErasure.as_str(), "GDPR_ERASURE");
    }

    #[test]
    fn audit_action_target_type() {
        assert_eq!(AuditAction::AgentRegister.target_type(), "AGENT");
        assert_eq!(AuditAction::AgentSuspend.target_type(), "AGENT");
        assert_eq!(AuditAction::AgentActivate.target_type(), "AGENT");
        assert_eq!(AuditAction::AgentStatusChange.target_type(), "AGENT");
        assert_eq!(AuditAction::TokenIssue.target_type(), "TOKEN");
        assert_eq!(AuditAction::TokenRevoke.target_type(), "TOKEN");
        assert_eq!(AuditAction::ShadowModeChange.target_type(), "SHADOW_MODE");
        assert_eq!(AuditAction::GdprErasure.target_type(), "AGENT");
    }
}
