//! SOC 2 evidence export helpers.
//!
//! Shared between the HTTP admin endpoint (`GET /irl/admin/evidence`) and the
//! standalone CLI binary (`irl-engine-evidence-export`).

use crate::errors::AppError;
use chrono::{DateTime, Utc};
use std::io::Write;

/// (created_at, operator_id, action, target_type, target_id, ip_address)
type AuditLogRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

pub async fn export_audit_log(
    pool: &sqlx::PgPool,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<String, AppError> {
    let rows: Vec<AuditLogRow> = sqlx::query_as(
        r#"
        SELECT
            created_at::text,
            operator_id,
            action,
            target_type,
            target_id,
            ip_address::text
        FROM irl.admin_audit_log
        WHERE created_at BETWEEN $1 AND $2
        ORDER BY created_at ASC
        "#,
    )
    .bind(from)
    .bind(to)
    .fetch_all(pool)
    .await?;

    let mut csv = String::from("created_at,operator_id,action,target_type,target_id,ip_address\n");
    for (ts, op, action, ttype, tid, ip) in rows {
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            ts,
            op,
            action,
            ttype.unwrap_or_default(),
            tid.unwrap_or_default(),
            ip.unwrap_or_default(),
        ));
    }
    Ok(csv)
}

pub async fn export_key_rotations(pool: &sqlx::PgPool) -> Result<String, AppError> {
    let rows: Vec<(i32, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT key_version, status, created_at::text, retired_at::text
        FROM irl.kms_key_metadata
        ORDER BY key_version ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut csv = String::from("key_version,status,created_at,retired_at\n");
    for (ver, status, created, retired) in rows {
        csv.push_str(&format!(
            "{},{},{},{}\n",
            ver,
            status,
            created,
            retired.unwrap_or_default(),
        ));
    }
    Ok(csv)
}

pub async fn export_policy_decisions(
    pool: &sqlx::PgPool,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<String, AppError> {
    let rows: Vec<(Option<String>, String, i64)> = sqlx::query_as(
        r#"
        SELECT mta_version, policy_result, COUNT(*)::bigint
        FROM irl.reasoning_traces
        WHERE txn_time BETWEEN $1 AND $2
        GROUP BY mta_version, policy_result
        ORDER BY mta_version, policy_result
        "#,
    )
    .bind(from)
    .bind(to)
    .fetch_all(pool)
    .await?;

    let mut csv = String::from("mta_version,policy_result,count\n");
    for (ver, result, count) in rows {
        csv.push_str(&format!(
            "{},{},{}\n",
            ver.unwrap_or_default(),
            result,
            count
        ));
    }
    Ok(csv)
}

/// Build an in-memory ZIP containing all four SOC 2 evidence artefacts.
pub async fn build_zip_for_range(
    pool: &sqlx::PgPool,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<u8>, AppError> {
    let audit_csv = export_audit_log(pool, from, to).await?;
    let key_csv = export_key_rotations(pool).await?;
    let decisions_csv = export_policy_decisions(pool, from, to).await?;

    let buf = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(buf);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("audit_log.csv", options)
        .map_err(|e| AppError::Serialization(e.to_string()))?;
    zip.write_all(audit_csv.as_bytes())
        .map_err(|e| AppError::Serialization(e.to_string()))?;

    zip.start_file("key_rotations.csv", options)
        .map_err(|e| AppError::Serialization(e.to_string()))?;
    zip.write_all(key_csv.as_bytes())
        .map_err(|e| AppError::Serialization(e.to_string()))?;

    zip.start_file("policy_decisions.csv", options)
        .map_err(|e| AppError::Serialization(e.to_string()))?;
    zip.write_all(decisions_csv.as_bytes())
        .map_err(|e| AppError::Serialization(e.to_string()))?;

    let manifest = format!(
        "IRL Engine SOC 2 Evidence Export\nGenerated: {}\nPeriod: {} to {}\nFiles:\n  audit_log.csv\n  key_rotations.csv\n  policy_decisions.csv\n",
        Utc::now().to_rfc3339(),
        from.format("%Y-%m-%d"),
        to.format("%Y-%m-%d"),
    );
    zip.start_file("MANIFEST.txt", options)
        .map_err(|e| AppError::Serialization(e.to_string()))?;
    zip.write_all(manifest.as_bytes())
        .map_err(|e| AppError::Serialization(e.to_string()))?;

    let cursor = zip
        .finish()
        .map_err(|e| AppError::Serialization(e.to_string()))?;
    Ok(cursor.into_inner())
}
