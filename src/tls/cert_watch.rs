use axum_server::tls_rustls::RustlsConfig;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::time::Duration;

/// Background task that watches cert/key PEM files for modifications and
/// hot-reloads the RustlsConfig without a process restart (MTLS-03).
///
/// Uses `spawn_blocking` for the notify sync channel to avoid blocking
/// the async runtime.
pub async fn spawn_cert_watcher(tls_config: RustlsConfig, cert_path: PathBuf, key_path: PathBuf) {
    let cert_path_for_watcher = cert_path.clone();
    let key_path_for_watcher = key_path.clone();

    tokio::task::spawn_blocking(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match RecommendedWatcher::new(tx, notify::Config::default()) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to create cert file watcher: {e}");
                return;
            }
        };

        if let Err(e) = watcher.watch(&cert_path_for_watcher, RecursiveMode::NonRecursive) {
            tracing::error!("Failed to watch cert file {:?}: {e}", cert_path_for_watcher);
            return;
        }
        if let Err(e) = watcher.watch(&key_path_for_watcher, RecursiveMode::NonRecursive) {
            tracing::error!("Failed to watch key file {:?}: {e}", key_path_for_watcher);
            return;
        }

        tracing::info!(
            "Cert watcher active on {:?} and {:?}",
            cert_path_for_watcher,
            key_path_for_watcher
        );

        loop {
            match rx.recv() {
                Ok(Ok(event)) if event.kind.is_modify() || event.kind.is_create() => {
                    tracing::info!("Cert file changed, debouncing 150ms then reloading TLS config");
                    std::thread::sleep(Duration::from_millis(150));
                    let config = tls_config.clone();
                    let cp = cert_path.clone();
                    let kp = key_path.clone();
                    let rt = tokio::runtime::Handle::current();
                    rt.block_on(async move {
                        match config.reload_from_pem_file(&cp, &kp).await {
                            Ok(_) => tracing::info!("TLS config hot-reloaded successfully"),
                            Err(e) => tracing::error!("TLS hot-reload failed: {e}"),
                        }
                    });
                }
                Ok(Err(e)) => {
                    tracing::warn!("Cert watcher event error: {e}");
                }
                Err(e) => {
                    tracing::warn!("Cert watcher channel closed: {e}");
                    break;
                }
                _ => {}
            }
        }
    })
    .await
    .ok();
}

/// Spawns a background task that logs WARN every hour when the server cert
/// is within 14 days of expiry (MTLS-04 expiry monitoring).
pub fn spawn_expiry_warn_task(server_cert_not_after: std::time::SystemTime) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match crate::tls::expiry::check_cert_expiry(server_cert_not_after) {
                crate::tls::expiry::CertExpiryStatus::ExpiringSoon { days_remaining } => {
                    tracing::warn!(
                        "CERT EXPIRY WARNING: server TLS certificate expires in {} day(s). \
                         Rotate certificate before clients are locked out.",
                        days_remaining
                    );
                }
                crate::tls::expiry::CertExpiryStatus::Expired => {
                    tracing::error!(
                        "CERT EXPIRED: server TLS certificate has expired. \
                         Clients will be rejected. Rotate certificate immediately."
                    );
                }
                crate::tls::expiry::CertExpiryStatus::Ok => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[tokio::test]
    async fn test_expiry_warn_task_does_not_panic() {
        let soon = SystemTime::now() + Duration::from_secs(5 * 86400);
        spawn_expiry_warn_task(soon);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}
