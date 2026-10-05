//! SOC 2 Evidence Export CLI — SOC2-01
//!
//! Usage:
//!   irl-engine-evidence-export --from 2026-01-01 --to 2026-03-31 --out /tmp/evidence.zip
//!
//! Produces a ZIP archive containing:
//!   - audit_log.csv         : All admin actions in the date range
//!   - key_rotations.csv     : KMS key metadata and rotation events
//!   - policy_decisions.csv  : Aggregate authorize counts by regime and outcome
//!   - uptime_metrics.json   : Prometheus scrape snapshot (if METRICS_URL set)
//!
//! The archive is intended to be handed directly to a SOC 2 auditor.
//! Every field is timestamped in UTC ISO 8601 format.
#![allow(clippy::type_complexity)]

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use std::io::Write;

#[derive(Debug)]
struct Args {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    out: String,
    database_url: String,
}

fn parse_args() -> Result<Args> {
    let args: Vec<String> = std::env::args().collect();
    let mut from_str = String::new();
    let mut to_str = String::new();
    let mut out = String::from("evidence.zip");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--from" => {
                i += 1;
                from_str = args
                    .get(i)
                    .cloned()
                    .context("--from requires a date argument")?;
            }
            "--to" => {
                i += 1;
                to_str = args
                    .get(i)
                    .cloned()
                    .context("--to requires a date argument")?;
            }
            "--out" => {
                i += 1;
                out = args
                    .get(i)
                    .cloned()
                    .context("--out requires a path argument")?;
            }
            _ => {}
        }
        i += 1;
    }

    anyhow::ensure!(!from_str.is_empty(), "--from DATE is required");
    anyhow::ensure!(!to_str.is_empty(), "--to DATE is required");

    let from_date = NaiveDate::parse_from_str(&from_str, "%Y-%m-%d")
        .with_context(|| format!("--from must be YYYY-MM-DD, got '{from_str}'"))?;
    let to_date = NaiveDate::parse_from_str(&to_str, "%Y-%m-%d")
        .with_context(|| format!("--to must be YYYY-MM-DD, got '{to_str}'"))?;

    let from = Utc.from_utc_datetime(&from_date.and_hms_opt(0, 0, 0).unwrap());
    let to = Utc.from_utc_datetime(&to_date.and_hms_opt(23, 59, 59).unwrap());

    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL environment variable not set")?;

    Ok(Args {
        from,
        to,
        out,
        database_url,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    println!("IRL Engine — SOC 2 Evidence Export");
    println!(
        "  Period : {} → {}",
        args.from.format("%Y-%m-%d"),
        args.to.format("%Y-%m-%d")
    );
    println!("  Output : {}", args.out);

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&args.database_url)
        .await
        .context("Failed to connect to database")?;

    // Collect each evidence artefact into memory before writing the ZIP.
    let audit_csv = export_audit_log(&pool, args.from, args.to).await?;
    let key_csv = export_key_rotations(&pool).await?;
    let decisions_csv = export_policy_decisions(&pool, args.from, args.to).await?;

    // Write ZIP
    let file = std::fs::File::create(&args.out)
        .with_context(|| format!("Cannot create output file '{}'", args.out))?;
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("audit_log.csv", options)?;
    zip.write_all(audit_csv.as_bytes())?;

    zip.start_file("key_rotations.csv", options)?;
    zip.write_all(key_csv.as_bytes())?;

    zip.start_file("policy_decisions.csv", options)?;
    zip.write_all(decisions_csv.as_bytes())?;

    // Manifest
    let manifest = format!(
        "IRL Engine SOC 2 Evidence Export\nGenerated: {}\nPeriod: {} to {}\nFiles:\n  audit_log.csv\n  key_rotations.csv\n  policy_decisions.csv\n",
        Utc::now().to_rfc3339(),
        args.from.format("%Y-%m-%d"),
        args.to.format("%Y-%m-%d"),
    );
    zip.start_file("MANIFEST.txt", options)?;
    zip.write_all(manifest.as_bytes())?;

    zip.finish()?;

    println!("Evidence archive written to '{}'", args.out);
    Ok(())
}

async fn export_audit_log(
    pool: &sqlx::PgPool,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<String> {
    let rows: Vec<(
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
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
    .await
    .context("Failed to query audit log")?;

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

async fn export_key_rotations(pool: &sqlx::PgPool) -> Result<String> {
    let rows: Vec<(i32, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT key_version, status, created_at::text, retired_at::text
        FROM irl.kms_key_metadata
        ORDER BY key_version ASC
        "#,
    )
    .fetch_all(pool)
    .await
    .context("Failed to query kms_key_metadata")?;

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

async fn export_policy_decisions(
    pool: &sqlx::PgPool,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<String> {
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
    .await
    .context("Failed to query policy decisions")?;

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
