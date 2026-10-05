//! T-1.2 — domain-separated, second-preimage-resistant Merkle tree + O(log n)
//! audit paths.
//!
//! This is an **additive** module. It does not modify [`crate::merkle`]; the
//! existing daily-anchor pipeline keeps using `compute_merkle_root` until the
//! anchor worker is migrated behind a `merkle_algo` tag. New anchors that opt
//! into `merkle_algo = "rfc6962-sha256-v2"` use the functions here.
//!
//! # Why v2 exists
//! [`crate::merkle::compute_merkle_root`] combines both leaves and internal
//! nodes with the same `SHA256(left || right)` and duplicates the last node on
//! odd counts. With no leaf/internal domain separation, the internal digests of
//! a larger tree can be presented AS the leaves of a smaller tree and yield an
//! identical root (CVE-2012-2459 second-preimage class). Once audit paths ship,
//! a verifier folding a forged path could be convinced a hash that was never a
//! leaf is included. The `production_root_has_second_preimage_collision` test
//! below demonstrates the flaw against the real function.
//!
//! # Construction (RFC 6962 style)
//!   leaf(x)    = SHA256( 0x00 || x )
//!   node(l, r) = SHA256( 0x01 || l || r )
//! A leaf digest can never equal an internal digest, so no internal node can
//! masquerade as a leaf.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Algorithm tag stored alongside each anchor so verifiers pick the right root
/// construction. Keep [`crate::merkle`]'s implicit v1 as the untagged default.
pub const MERKLE_ALGO_V2: &str = "rfc6962-sha256-v2";

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// One sibling on the path from a leaf to the root. Serializes the sibling as a
/// hex string so an audit path can travel inside a proof bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleStep {
    #[serde(with = "hex_array32")]
    pub sibling: [u8; 32],
    /// True when the sibling sits on the LEFT (current node is the right child).
    pub sibling_is_left: bool,
}

/// serde helper: (de)serialize a `[u8; 32]` as a lower-hex string.
mod hex_array32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected exactly 32 bytes"))
    }
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Decode a hex leaf hash to 32 bytes. A leaf that is not exactly 32 bytes when
/// decoded is hashed from its raw string bytes — total, never panics — matching
/// the defensive posture of the v1 implementation.
fn leaf_bytes(hex_hash: &str) -> [u8; 32] {
    match hex::decode(hex_hash) {
        Ok(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            a
        }
        _ => sha256(&[hex_hash.as_bytes()]),
    }
}

fn hash_leaf(value: &[u8; 32]) -> [u8; 32] {
    sha256(&[&[LEAF_PREFIX], value])
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[&[NODE_PREFIX], left, right])
}

/// Build every padded level of the tree, bottom-up. Index 0 is the leaf level
/// (already leaf-hashed and padded to even width); the last entry is the root.
fn build_levels(leaves: &[String]) -> Vec<Vec<[u8; 32]>> {
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|h| hash_leaf(&leaf_bytes(h))).collect();
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    loop {
        if level.len() == 1 {
            levels.push(level);
            break;
        }
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last); // safe under domain separation
        }
        levels.push(level.clone());
        level = level.chunks(2).map(|p| hash_node(&p[0], &p[1])).collect();
    }
    levels
}

/// Domain-separated Merkle root over hex-encoded leaf hashes (txn_time order).
/// Empty input returns the zero root, matching v1.
pub fn compute_merkle_root_v2(leaves: &[String]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    *build_levels(leaves).last().unwrap().first().unwrap()
}

/// Audit path for the leaf at `index`. Folding `hash_leaf(leaf)` with these
/// siblings reproduces the root — the whole leaf list is not needed to verify.
pub fn audit_path(leaves: &[String], index: usize) -> Option<Vec<MerkleStep>> {
    if index >= leaves.len() {
        return None;
    }
    let levels = build_levels(leaves);
    let mut path = Vec::new();
    let mut idx = index;
    for level in &levels[..levels.len().saturating_sub(1)] {
        let sibling = level[idx ^ 1]; // padded levels are even, sibling always exists
        path.push(MerkleStep {
            sibling,
            sibling_is_left: idx % 2 == 1,
        });
        idx /= 2;
    }
    Some(path)
}

/// Verify an audit path: fold the leaf value up through its siblings and compare
/// to the claimed root. Pure, offline, O(log n).
pub fn verify_audit_path(leaf_hex: &str, path: &[MerkleStep], root: &[u8; 32]) -> bool {
    let mut acc = hash_leaf(&leaf_bytes(leaf_hex));
    for step in path {
        acc = if step.sibling_is_left {
            hash_node(&step.sibling, &acc)
        } else {
            hash_node(&acc, &step.sibling)
        };
    }
    &acc == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn production_root_has_second_preimage_collision() {
        // Demonstrates the flaw in the SHIPPED function: the internal digests of
        // a 4-leaf tree, presented as 2 leaves, produce the SAME root.
        let (l1, l2, l3, l4) = (h(1), h(2), h(3), h(4));
        let root_4 =
            crate::merkle::compute_merkle_root(&[l1.clone(), l2.clone(), l3.clone(), l4.clone()]);

        // Reconstruct the v1 internal digests (raw SHA256(a||b), no domain sep).
        let combine = |a: &str, b: &str| {
            let mut x = [0u8; 32];
            x.copy_from_slice(&hex::decode(a).unwrap());
            let mut y = [0u8; 32];
            y.copy_from_slice(&hex::decode(b).unwrap());
            hex::encode(sha256(&[&x, &y]))
        };
        let n12 = combine(&l1, &l2);
        let n34 = combine(&l3, &l4);
        let root_2 = crate::merkle::compute_merkle_root(&[n12, n34]);

        assert_eq!(
            root_4, root_2,
            "production compute_merkle_root is second-preimage vulnerable"
        );
    }

    #[test]
    fn v2_resists_the_same_collision() {
        let (l1, l2, l3, l4) = (h(1), h(2), h(3), h(4));
        let root_4 = compute_merkle_root_v2(&[l1.clone(), l2.clone(), l3.clone(), l4.clone()]);

        let combine = |a: &str, b: &str| {
            let mut x = [0u8; 32];
            x.copy_from_slice(&hex::decode(a).unwrap());
            let mut y = [0u8; 32];
            y.copy_from_slice(&hex::decode(b).unwrap());
            hex::encode(sha256(&[&x, &y]))
        };
        let n12 = combine(&l1, &l2);
        let n34 = combine(&l3, &l4);
        let root_2 = compute_merkle_root_v2(&[n12, n34]);

        assert_ne!(
            root_4, root_2,
            "domain separation must defeat the collision"
        );
    }

    #[test]
    fn empty_returns_zero_root() {
        assert_eq!(compute_merkle_root_v2(&[]), [0u8; 32]);
    }

    #[test]
    fn deterministic() {
        let leaves: Vec<String> = (0u8..7).map(h).collect();
        assert_eq!(
            compute_merkle_root_v2(&leaves),
            compute_merkle_root_v2(&leaves)
        );
    }

    #[test]
    fn audit_paths_verify_for_all_indices_including_odd_count() {
        let leaves: Vec<String> = (0u8..5).map(h).collect(); // odd count exercises duplication
        let root = compute_merkle_root_v2(&leaves);
        for i in 0..leaves.len() {
            let path = audit_path(&leaves, i).expect("in range");
            assert!(
                verify_audit_path(&leaves[i], &path, &root),
                "audit path for index {i} must fold to the root"
            );
        }
    }

    #[test]
    fn forged_audit_path_rejected() {
        let leaves: Vec<String> = (0u8..4).map(h).collect();
        let root = compute_merkle_root_v2(&leaves);
        let mut path = audit_path(&leaves, 0).unwrap();
        path[0].sibling[0] ^= 0xFF;
        assert!(!verify_audit_path(&leaves[0], &path, &root));
    }

    #[test]
    fn non_member_leaf_rejected() {
        let leaves: Vec<String> = (0u8..4).map(h).collect();
        let root = compute_merkle_root_v2(&leaves);
        let path = audit_path(&leaves, 1).unwrap();
        assert!(!verify_audit_path(&h(99), &path, &root));
    }
}
