//! Regime-change webhook worker.
//!
//! Polls the MTA every 5 s. On regime_id change fires an HMAC-SHA256 signed
//! POST to WEBHOOK_URL with `X-IRL-Signature: sha256=<hex>`.
//!
//! Verification on the receiver:
//!   sig = HMAC-SHA256(secret, raw_body_bytes)
//!   assert request.headers["X-IRL-Signature"] == "sha256=" + hex(sig)

use crate::mta::MtaClient;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

pub async fn run_webhook_worker(
    mta_client: Arc<dyn MtaClient>,
    webhook_url: String,
    webhook_secret: String,
) {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");

    let mut last_regime_id: Option<u8> = None;
    let mut interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        interval.tick().await;

        let mta = match mta_client.fetch_verified().await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Webhook worker: MTA fetch failed: {e}");
                continue;
            }
        };

        let changed = last_regime_id.is_none_or(|prev| prev != mta.regime_id);
        last_regime_id = Some(mta.regime_id);

        if !changed {
            continue;
        }

        let payload = serde_json::json!({
            "event": "regime_change",
            "regime_id": mta.regime_id,
            "regime_label": mta.regime_label,
            "mta_version": mta.version,
            "mta_hash": mta.hash,
            "risk_level": mta.risk_level,
            "broadcast_time": mta.broadcast_time,
        });

        let body = match serde_json::to_string(&payload) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Webhook worker: serialization failed: {e}");
                continue;
            }
        };

        let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(body.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        match http
            .post(&webhook_url)
            .header("Content-Type", "application/json")
            .header("X-IRL-Signature", format!("sha256={signature}"))
            .body(body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(
                    regime_id = mta.regime_id,
                    regime_label = %mta.regime_label,
                    "Regime change webhook delivered"
                );
            }
            Ok(resp) => {
                tracing::warn!(
                    status = resp.status().as_u16(),
                    regime_id = mta.regime_id,
                    "Regime change webhook non-2xx response"
                );
            }
            Err(e) => {
                tracing::warn!(
                    regime_id = mta.regime_id,
                    "Regime change webhook failed: {e}"
                );
            }
        }
    }
}
