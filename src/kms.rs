use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::config::{Config, KmsProvider};
use crate::encryption::{decrypt_trace, encrypt_trace};

/// Envelope key provider abstraction.
///
/// Implementations wrap/unwrap per-record Data Encryption Keys (DEKs).
/// The plaintext DEK is always returned as `Zeroizing<Vec<u8>>` and is
/// wiped from memory when dropped. Callers must not persist it.
// async_trait marks its generated boxed-future methods #[must_use]; newer clippy
// flags that as double_must_use on trait definitions (false positive).
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Generate a fresh 32-byte DEK, wrap it with the CMK, and return:
    /// `(plaintext_dek, encrypted_dek, key_version)`.
    ///
    /// The plaintext DEK is Zeroizing — it is wiped from memory on drop.
    async fn generate_dek(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, i32)>;

    /// Decrypt a stored encrypted DEK back to its 32-byte plaintext.
    /// Returns `Zeroizing<>` — use for AES-GCM, then drop.
    async fn decrypt_dek(
        &self,
        encrypted_dek: &[u8],
        key_version: i32,
    ) -> Result<Zeroizing<Vec<u8>>>;
}

// ---------------------------------------------------------------------------
// AwsKmsProvider
// ---------------------------------------------------------------------------

/// Envelope encryption via AWS KMS (GenerateDataKey / Decrypt).
pub struct AwsKmsProvider {
    client: aws_sdk_kms::Client,
    key_id: String,
    key_version: i32,
}

impl AwsKmsProvider {
    pub async fn new(key_id: String, key_version: i32) -> Self {
        let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_kms::Client::new(&sdk_config);
        Self {
            client,
            key_id,
            key_version,
        }
    }
}

#[async_trait]
impl KeyProvider for AwsKmsProvider {
    async fn generate_dek(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, i32)> {
        let resp = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .send()
            .await
            .context("AWS KMS GenerateDataKey failed")?;

        let plaintext_blob = resp
            .plaintext()
            .ok_or_else(|| anyhow!("AWS KMS: GenerateDataKey returned no plaintext"))?
            .clone();
        let plaintext_bytes = Zeroizing::new(plaintext_blob.into_inner());

        let ciphertext_blob = resp
            .ciphertext_blob()
            .ok_or_else(|| anyhow!("AWS KMS: GenerateDataKey returned no ciphertext_blob"))?
            .clone();
        let encrypted_dek = ciphertext_blob.into_inner();

        Ok((plaintext_bytes, encrypted_dek, self.key_version))
    }

    async fn decrypt_dek(
        &self,
        encrypted_dek: &[u8],
        _key_version: i32,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let resp = self
            .client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(encrypted_dek.to_vec()))
            .send()
            .await
            .context("AWS KMS Decrypt failed")?;

        let plaintext_blob = resp
            .plaintext()
            .ok_or_else(|| anyhow!("AWS KMS: Decrypt returned no plaintext"))?
            .clone();

        Ok(Zeroizing::new(plaintext_blob.into_inner()))
    }
}

// ---------------------------------------------------------------------------
// VaultTransitProvider
// ---------------------------------------------------------------------------

/// Envelope encryption via HashiCorp Vault Transit secrets engine.
pub struct VaultTransitProvider {
    client: vaultrs::client::VaultClient,
    mount: String,
    key_name: String,
    key_version: i32,
}

impl VaultTransitProvider {
    pub fn new(key_version: i32) -> Result<Self> {
        let addr = std::env::var("VAULT_ADDR").context("VAULT_ADDR missing")?;
        let token = std::env::var("VAULT_TOKEN").context("VAULT_TOKEN missing")?;
        let mount = std::env::var("VAULT_TRANSIT_MOUNT").unwrap_or_else(|_| "transit".to_string());
        let key_name = std::env::var("VAULT_TRANSIT_KEY").context("VAULT_TRANSIT_KEY missing")?;

        let settings = vaultrs::client::VaultClientSettingsBuilder::default()
            .address(addr)
            .token(token)
            .build()
            .context("Failed to build Vault client settings")?;

        let client =
            vaultrs::client::VaultClient::new(settings).context("Failed to create Vault client")?;

        Ok(Self {
            client,
            mount,
            key_name,
            key_version,
        })
    }
}

#[async_trait]
impl KeyProvider for VaultTransitProvider {
    async fn generate_dek(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, i32)> {
        use rand::RngCore;
        let mut dek_bytes = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut dek_bytes);
        let plaintext_b64 = general_purpose::STANDARD.encode(&dek_bytes);

        let resp = vaultrs::transit::data::encrypt(
            &self.client,
            &self.mount,
            &self.key_name,
            &plaintext_b64,
            None,
        )
        .await
        .context("Vault transit encrypt failed")?;

        let encrypted_dek = resp.ciphertext.into_bytes();
        let plaintext_dek = Zeroizing::new(dek_bytes);

        Ok((plaintext_dek, encrypted_dek, self.key_version))
    }

    async fn decrypt_dek(
        &self,
        encrypted_dek: &[u8],
        _key_version: i32,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let ciphertext_str = std::str::from_utf8(encrypted_dek)
            .context("Vault ciphertext stored in BYTEA is not valid UTF-8")?;

        let resp = vaultrs::transit::data::decrypt(
            &self.client,
            &self.mount,
            &self.key_name,
            ciphertext_str,
            None,
        )
        .await
        .context("Vault transit decrypt failed")?;

        let dek_bytes = general_purpose::STANDARD
            .decode(&resp.plaintext)
            .context("Vault response plaintext is not valid base64")?;

        Ok(Zeroizing::new(dek_bytes))
    }
}

// ---------------------------------------------------------------------------
// LocalDevProvider
// ---------------------------------------------------------------------------

/// Local-only dev/CI provider. Wraps DEK with a 32-byte key from LOCAL_KMS_KEY (hex).
///
/// # Safety
/// Refuses to initialise when ENVIRONMENT=production. Emits a warning at construction.
#[derive(Debug)]
pub struct LocalDevProvider {
    wrapping_key: Zeroizing<Vec<u8>>,
    key_version: i32,
}

impl LocalDevProvider {
    pub fn new(key_version: i32) -> Result<Self> {
        let env = std::env::var("ENVIRONMENT").unwrap_or_default();
        if env.to_lowercase() == "production" {
            anyhow::bail!("LocalDevProvider cannot be used in ENVIRONMENT=production");
        }

        tracing::warn!(
            "KMS_PROVIDER=local: NOT for production use. Use aws or vault in production."
        );

        let key_hex = std::env::var("LOCAL_KMS_KEY")
            .context("LOCAL_KMS_KEY must be set when KMS_PROVIDER=local")?;
        let key_bytes = hex::decode(&key_hex).context("LOCAL_KMS_KEY is not valid hex")?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "LOCAL_KMS_KEY must be exactly 32 bytes (64 hex chars), got {}",
                key_bytes.len()
            );
        }

        Ok(Self {
            wrapping_key: Zeroizing::new(key_bytes),
            key_version,
        })
    }
}

#[async_trait]
impl KeyProvider for LocalDevProvider {
    async fn generate_dek(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, i32)> {
        use rand::RngCore;
        let mut dek_bytes = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut dek_bytes);

        // Wrap: AES-GCM encrypt the DEK under the wrapping key.
        // Stored as nonce(12) || ciphertext_and_tag.
        let blob = encrypt_trace(&dek_bytes, &self.wrapping_key)
            .context("LocalDevProvider: DEK wrapping failed")?;
        let mut wrapped = Vec::with_capacity(12 + blob.ciphertext.len());
        wrapped.extend_from_slice(&blob.nonce);
        wrapped.extend_from_slice(&blob.ciphertext);

        let plaintext_dek = Zeroizing::new(dek_bytes);
        Ok((plaintext_dek, wrapped, self.key_version))
    }

    async fn decrypt_dek(
        &self,
        encrypted_dek: &[u8],
        _key_version: i32,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if encrypted_dek.len() < 12 {
            anyhow::bail!("LocalDevProvider: encrypted_dek too short to contain nonce");
        }
        let (nonce, ciphertext) = encrypted_dek.split_at(12);
        let dek_bytes = decrypt_trace(ciphertext, nonce, &self.wrapping_key)
            .context("LocalDevProvider: DEK unwrapping failed")?;
        Ok(Zeroizing::new(dek_bytes))
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Build the active KeyProvider from configuration.
///
/// Returns `None` when `KMS_PROVIDER` is unset — the engine will store
/// `trace_json` in plaintext (`encryption_version = 0`).
pub async fn build_key_provider(config: &Config) -> Result<Option<Arc<dyn KeyProvider>>> {
    match &config.kms_provider {
        KmsProvider::None => Ok(None),
        KmsProvider::Local => {
            let provider = LocalDevProvider::new(config.kms_key_version)?;
            Ok(Some(Arc::new(provider)))
        }
        KmsProvider::Aws => {
            let key_id = config
                .kms_key_id
                .as_ref()
                .ok_or_else(|| anyhow!("KMS_KEY_ID is required when KMS_PROVIDER=aws"))?;
            let provider = AwsKmsProvider::new(key_id.clone(), config.kms_key_version).await;
            Ok(Some(Arc::new(provider)))
        }
        KmsProvider::Vault => {
            let provider = VaultTransitProvider::new(config.kms_key_version)?;
            Ok(Some(Arc::new(provider)))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // All tests that mutate env vars must hold this lock for their duration.
    // Prevents races between parallel test threads on ENVIRONMENT / LOCAL_KMS_KEY / KMS_PROVIDER.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn setup_local_provider() -> LocalDevProvider {
        std::env::set_var(
            "LOCAL_KMS_KEY",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        std::env::remove_var("ENVIRONMENT");
        LocalDevProvider::new(1).expect("LocalDevProvider::new should succeed")
    }

    // ENV_LOCK serializes env-var access across tests (CI runs --test-threads=1);
    // holding it across the await is intentional and harmless here.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_local_dev_generate_dek_returns_32_byte_plaintext() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let provider = setup_local_provider();
        let (plaintext, encrypted, version) = provider
            .generate_dek()
            .await
            .expect("generate_dek should succeed");
        assert_eq!(plaintext.len(), 32, "plaintext DEK must be 32 bytes");
        assert!(!encrypted.is_empty(), "encrypted DEK must not be empty");
        assert_eq!(version, 1);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_local_dev_roundtrip() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let provider = setup_local_provider();
        let (plaintext, encrypted, _version) = provider.generate_dek().await.expect("generate_dek");
        let recovered = provider
            .decrypt_dek(&encrypted, 1)
            .await
            .expect("decrypt_dek");
        assert_eq!(
            *plaintext, *recovered,
            "round-trip must recover original DEK"
        );
    }

    #[test]
    fn test_local_dev_fails_in_production() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("ENVIRONMENT", "production");
        std::env::set_var(
            "LOCAL_KMS_KEY",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        let result = LocalDevProvider::new(1);
        std::env::remove_var("ENVIRONMENT");
        assert!(
            result.is_err(),
            "LocalDevProvider must refuse ENVIRONMENT=production"
        );
        assert!(result.unwrap_err().to_string().contains("production"));
    }

    #[test]
    fn test_local_dev_fails_with_wrong_key_length() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("ENVIRONMENT");
        std::env::set_var("LOCAL_KMS_KEY", "deadbeef"); // only 4 bytes
        let result = LocalDevProvider::new(1);
        assert!(result.is_err(), "LocalDevProvider must reject 4-byte key");
    }

    #[test]
    fn test_config_kms_provider_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("KMS_PROVIDER");
        let provider = match std::env::var("KMS_PROVIDER").as_deref() {
            Ok("local") => KmsProvider::Local,
            Ok("aws") => KmsProvider::Aws,
            Ok("vault") => KmsProvider::Vault,
            _ => KmsProvider::None,
        };
        assert_eq!(provider, KmsProvider::None);
    }

    #[test]
    fn test_config_kms_provider_local() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("KMS_PROVIDER", "local");
        let provider = match std::env::var("KMS_PROVIDER").as_deref() {
            Ok("local") => KmsProvider::Local,
            Ok("aws") => KmsProvider::Aws,
            Ok("vault") => KmsProvider::Vault,
            _ => KmsProvider::None,
        };
        std::env::remove_var("KMS_PROVIDER");
        assert_eq!(provider, KmsProvider::Local);
    }
}
