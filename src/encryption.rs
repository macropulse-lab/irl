use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};

/// AES-256-GCM encrypted payload.
///
/// `ciphertext` contains the encrypted bytes with the 16-byte GCM authentication
/// tag appended in-band (so `len == plaintext_len + 16`).
/// `nonce` is the 96-bit (12-byte) IV — generated fresh per call from OS entropy.
#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    /// AES-GCM ciphertext with 16-byte GCM auth tag appended in-band.
    /// len = plaintext_len + 16
    pub ciphertext: Vec<u8>,
    /// 96-bit (12-byte) nonce. Store in trace_nonce BYTEA column.
    pub nonce: [u8; 12],
}

/// Encrypt plaintext bytes under a 32-byte DEK using AES-256-GCM.
/// Nonce is generated from OS entropy via OsRng — never reused.
///
/// # Panics
/// Panics if `dek` is not exactly 32 bytes.
pub fn encrypt_trace(plaintext: &[u8], dek: &[u8]) -> anyhow::Result<EncryptedBlob> {
    assert_eq!(
        dek.len(),
        32,
        "DEK must be exactly 32 bytes for AES-256-GCM"
    );

    let key = Key::<Aes256Gcm>::from_slice(dek);
    let cipher = Aes256Gcm::new(key);

    let nonce_generic = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce_bytes: [u8; 12] = nonce_generic.into();

    let ciphertext = cipher
        .encrypt(&nonce_generic, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?;

    Ok(EncryptedBlob {
        ciphertext,
        nonce: nonce_bytes,
    })
}

/// Decrypt AES-256-GCM ciphertext. Returns Err on tag mismatch (tamper detected).
///
/// # Panics
/// Panics if `dek` is not exactly 32 bytes.
///
/// # Errors
/// Returns `Err` if the nonce is not 12 bytes, or if decryption fails (tag mismatch).
pub fn decrypt_trace(ciphertext: &[u8], nonce: &[u8], dek: &[u8]) -> anyhow::Result<Vec<u8>> {
    assert_eq!(
        dek.len(),
        32,
        "DEK must be exactly 32 bytes for AES-256-GCM"
    );

    if nonce.len() != 12 {
        anyhow::bail!("Nonce must be exactly 12 bytes, got {}", nonce.len());
    }

    let key = Key::<Aes256Gcm>::from_slice(dek);
    let cipher = Aes256Gcm::new(key);
    let nonce_arr = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce_arr, ciphertext)
        .map_err(|_| anyhow::anyhow!("AES-GCM decryption failed: authentication tag mismatch"))?;

    Ok(plaintext)
}

/// Wrap raw ciphertext bytes in the JSONB-safe envelope: `{"v":1,"data":"<base64>"}`.
///
/// PostgreSQL JSONB rejects raw binary — this wrapper ensures valid JSON at all times.
pub fn wrap_ciphertext_for_jsonb(ciphertext: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "v": 1,
        "data": general_purpose::STANDARD.encode(ciphertext),
    })
}

/// Extract raw ciphertext bytes from a JSONB wrapper produced by `wrap_ciphertext_for_jsonb`.
///
/// # Errors
/// Returns `Err` if the value is missing required fields, has wrong version, or base64 is invalid.
pub fn extract_ciphertext_from_jsonb(value: &serde_json::Value) -> anyhow::Result<Vec<u8>> {
    let v = value
        .get("v")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow::anyhow!("JSONB wrapper missing 'v' field"))?;

    if v != 1 {
        anyhow::bail!("Unsupported JSONB wrapper version: {}", v);
    }

    let data_str = value
        .get("data")
        .and_then(|d| d.as_str())
        .ok_or_else(|| anyhow::anyhow!("JSONB wrapper missing 'data' string field"))?;

    let bytes = general_purpose::STANDARD
        .decode(data_str)
        .map_err(|e| anyhow::anyhow!("JSONB wrapper 'data' is not valid base64: {}", e))?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dek() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    #[test]
    fn test_encrypt_returns_ciphertext_with_auth_tag() {
        let dek = test_dek();
        let plaintext = b"hello world, this is a test payload";
        let blob = encrypt_trace(plaintext, &dek).expect("encryption should succeed");

        // GCM appends 16-byte auth tag in-band
        assert_eq!(blob.ciphertext.len(), plaintext.len() + 16);
        assert_eq!(blob.nonce.len(), 12);
    }

    #[test]
    fn test_roundtrip_encrypt_decrypt() {
        let dek = test_dek();
        let plaintext = b"round-trip test payload 12345";

        let blob = encrypt_trace(plaintext, &dek).expect("encryption should succeed");
        let recovered =
            decrypt_trace(&blob.ciphertext, &blob.nonce, &dek).expect("decryption should succeed");

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_dek_fails() {
        let dek = test_dek();
        let wrong_dek = vec![0xFFu8; 32];
        let plaintext = b"secret data";

        let blob = encrypt_trace(plaintext, &dek).expect("encryption should succeed");
        let result = decrypt_trace(&blob.ciphertext, &blob.nonce, &wrong_dek);

        assert!(result.is_err(), "decryption with wrong DEK must fail");
    }

    #[test]
    fn test_decrypt_with_corrupted_ciphertext_fails() {
        let dek = test_dek();
        let plaintext = b"secret data";

        let blob = encrypt_trace(plaintext, &dek).expect("encryption should succeed");
        let mut corrupted = blob.ciphertext.clone();
        // Flip a byte in the middle of the ciphertext
        corrupted[0] ^= 0xFF;

        let result = decrypt_trace(&corrupted, &blob.nonce, &dek);
        assert!(
            result.is_err(),
            "decryption of corrupted ciphertext must fail"
        );
    }

    #[test]
    fn test_different_nonces_for_same_plaintext() {
        let dek = test_dek();
        let plaintext = b"same plaintext";

        let blob1 = encrypt_trace(plaintext, &dek).expect("first encryption");
        let blob2 = encrypt_trace(plaintext, &dek).expect("second encryption");

        // OsRng should never produce the same 96-bit nonce twice in practice
        assert_ne!(
            blob1.nonce, blob2.nonce,
            "nonces must differ across calls (collision probability is negligible at 96 bits)"
        );
    }

    #[test]
    fn test_wrap_ciphertext_for_jsonb_structure() {
        let ciphertext = b"some raw ciphertext bytes";
        let wrapped = wrap_ciphertext_for_jsonb(ciphertext);

        assert_eq!(wrapped["v"], 1, "'v' must be 1");
        let data = wrapped["data"].as_str().expect("'data' must be a string");
        assert!(!data.is_empty(), "'data' must be non-empty");
    }

    #[test]
    fn test_jsonb_wrapper_roundtrip() {
        let original = b"raw ciphertext for jsonb test 0123456789";
        let wrapped = wrap_ciphertext_for_jsonb(original);
        let recovered = extract_ciphertext_from_jsonb(&wrapped).expect("extraction should succeed");

        assert_eq!(recovered, original);
    }

    #[test]
    fn test_extract_ciphertext_missing_fields() {
        let bad_value = serde_json::json!({"v": 1});
        assert!(extract_ciphertext_from_jsonb(&bad_value).is_err());

        let bad_version = serde_json::json!({"v": 2, "data": "aGVsbG8="});
        assert!(extract_ciphertext_from_jsonb(&bad_version).is_err());

        let missing_v = serde_json::json!({"data": "aGVsbG8="});
        assert!(extract_ciphertext_from_jsonb(&missing_v).is_err());
    }
}
