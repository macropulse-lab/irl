//! Completing OpenTimestamps receipts without the `ots` CLI.
//!
//! A calendar's first answer to `POST /digest` is a timestamp that ends in a
//! *pending* attestation ("I will commit this to Bitcoin"). Once the
//! calendar's transaction confirms, `GET {calendar}/timestamp/{commitment}`
//! returns the path from that commitment to a Bitcoin block header. Splicing
//! that path in place of the pending attestation yields a complete receipt
//! that verifies against Bitcoin alone, even if the calendar disappears.
//!
//! This module is pure: it parses the binary timestamp format, finds pending
//! attestations, and splices upgrades. Network and database live in
//! [`crate::merkle`]. Only the operations calendars emit are supported
//! (sha256, append, prepend, reverse, hexlify); anything else is an error,
//! never a guess.

use sha2::{Digest, Sha256};
use std::ops::Range;

const TAG_ATTESTATION: u8 = 0x00;
const TAG_FORK: u8 = 0xff;
const OP_SHA256: u8 = 0x08;
const OP_APPEND: u8 = 0xf0;
const OP_PREPEND: u8 = 0xf1;
const OP_REVERSE: u8 = 0xf2;
const OP_HEXLIFY: u8 = 0xf3;

const PENDING_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const BITCOIN_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// Bounds that keep a hostile or corrupt timestamp from exhausting memory or stack.
const MAX_DEPTH: usize = 256;
const MAX_MSG_LEN: usize = 4096;
const MAX_VARBYTES: usize = 8192;
const MAX_URI_LEN: usize = 1000;

/// Calendars a stored receipt may point the engine at. Exact `https://host`
/// match: the URI comes from a calendar response, so it is never trusted to
/// name an arbitrary host (SSRF).
pub const CALENDAR_HOSTS: &[&str] = &[
    "alice.btc.calendar.opentimestamps.org",
    "bob.btc.calendar.opentimestamps.org",
    "finney.calendar.eternitywall.com",
    "btc.calendar.catallaxy.com",
];

/// A pending attestation found in a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The message the calendar promised to commit; the upgrade is keyed by it.
    pub commitment: Vec<u8>,
    pub uri: String,
    /// Byte range of the attestation (`0x00`, tag, payload) in the receipt.
    span: Range<usize>,
    /// True when the attestation is its node's last child (no fork marker before it).
    is_last: bool,
}

/// Everything [`scan`] learned about a timestamp.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scan {
    pub pending: Vec<Pending>,
    pub bitcoin_heights: Vec<u64>,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, String> {
        let b = *self.buf.get(self.pos).ok_or("timestamp truncated")?;
        self.pos += 1;
        Ok(b)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len());
        let end = end.ok_or("timestamp truncated")?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Unsigned LEB128, as OpenTimestamps encodes lengths and block heights.
    fn varuint(&mut self) -> Result<u64, String> {
        let mut value: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("varuint too long".into())
    }

    fn varbytes(&mut self, max: usize) -> Result<&'a [u8], String> {
        let len = usize::try_from(self.varuint()?).map_err(|_| "length overflow")?;
        if len > max {
            return Err(format!("field of {len} bytes exceeds {max}"));
        }
        self.bytes(len)
    }

    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Parse the children of the node whose message is `msg`; return each child's span.
fn node(
    r: &mut Reader,
    msg: &[u8],
    depth: usize,
    out: &mut Scan,
) -> Result<Vec<Range<usize>>, String> {
    if depth > MAX_DEPTH {
        return Err("timestamp nested too deeply".into());
    }
    let mut spans = Vec::new();
    loop {
        let tag = r.byte()?;
        let forked = tag == TAG_FORK;
        let start = if forked { r.pos } else { r.pos - 1 };
        let tag = if forked { r.byte()? } else { tag };
        child(r, tag, msg, depth, !forked, out)?;
        spans.push(start..r.pos);
        if !forked {
            return Ok(spans);
        }
    }
}

fn child(
    r: &mut Reader,
    tag: u8,
    msg: &[u8],
    depth: usize,
    is_last: bool,
    out: &mut Scan,
) -> Result<(), String> {
    if tag == TAG_ATTESTATION {
        let start = r.pos - 1;
        let kind = r.bytes(8)?;
        let payload = r.varbytes(MAX_VARBYTES)?;
        if kind == PENDING_TAG {
            let uri = Reader::new(payload).varbytes(MAX_URI_LEN)?;
            let uri = String::from_utf8(uri.to_vec()).map_err(|_| "pending URI is not UTF-8")?;
            out.pending.push(Pending {
                commitment: msg.to_vec(),
                uri,
                span: start..r.pos,
                is_last,
            });
        } else if kind == BITCOIN_TAG {
            out.bitcoin_heights.push(Reader::new(payload).varuint()?);
        }
        return Ok(());
    }
    let next: Vec<u8> = match tag {
        OP_SHA256 => Sha256::digest(msg).to_vec(),
        OP_APPEND => [msg, r.varbytes(MAX_MSG_LEN)?].concat(),
        OP_PREPEND => [r.varbytes(MAX_MSG_LEN)?, msg].concat(),
        OP_REVERSE => msg.iter().rev().copied().collect(),
        OP_HEXLIFY => hex::encode(msg).into_bytes(),
        other => return Err(format!("unsupported timestamp operation 0x{other:02x}")),
    };
    if next.len() > MAX_MSG_LEN {
        return Err("timestamp message too long".into());
    }
    node(r, &next, depth + 1, out).map(|_| ())
}

/// Parse a whole serialized timestamp for `digest`. Trailing bytes are an error.
pub fn scan(timestamp: &[u8], digest: &[u8]) -> Result<Scan, String> {
    let mut r = Reader::new(timestamp);
    let mut out = Scan::default();
    node(&mut r, digest, 0, &mut out)?;
    if !r.at_end() {
        return Err("trailing bytes after timestamp".into());
    }
    Ok(out)
}

/// The upgrade URL for a pending attestation, or None when its calendar is not allowlisted.
pub fn upgrade_url(pending: &Pending) -> Option<String> {
    let host = pending.uri.strip_prefix("https://")?;
    CALENDAR_HOSTS.contains(&host).then(|| {
        format!(
            "{}/timestamp/{}",
            pending.uri,
            hex::encode(&pending.commitment)
        )
    })
}

/// Replace `pending` in `receipt` with the calendar's `upgrade` (a timestamp for
/// `pending.commitment`). The upgrade must reach a Bitcoin attestation; the
/// result is re-parsed against `digest` before it is returned.
pub fn splice(
    receipt: &[u8],
    digest: &[u8],
    pending: &Pending,
    upgrade: &[u8],
) -> Result<Vec<u8>, String> {
    let mut r = Reader::new(upgrade);
    let mut found = Scan::default();
    let children = node(&mut r, &pending.commitment, 0, &mut found)?;
    if !r.at_end() {
        return Err("trailing bytes after upgrade".into());
    }
    if found.bitcoin_heights.is_empty() {
        return Err("upgrade has no Bitcoin attestation yet".into());
    }

    // Re-emit the upgrade's children as siblings in the pending attestation's
    // slot. Every child that is followed by another sibling needs a fork
    // marker; the slot already carries one when the pending was not last.
    let mut replacement = Vec::with_capacity(upgrade.len() + children.len());
    let count = children.len();
    for (i, span) in children.into_iter().enumerate() {
        // Final slot: every child but the last gets a marker. Non-final slot:
        // the slot's own marker covers the first child, the rest get one each.
        let needs_fork = if pending.is_last {
            i + 1 < count
        } else {
            i > 0
        };
        if needs_fork {
            replacement.push(TAG_FORK);
        }
        replacement.extend_from_slice(&upgrade[span]);
    }

    let spliced = [
        &receipt[..pending.span.start],
        &replacement,
        &receipt[pending.span.end..],
    ]
    .concat();
    let check = scan(&spliced, digest)?;
    if check.bitcoin_heights.is_empty() {
        return Err("spliced receipt lost its Bitcoin attestation".into());
    }
    Ok(spliced)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real data: anchor c98d35d7 (2026-10-05 18:50–21:23 UTC) and alice's
    // upgrade for it, captured 2026-10-06. Bitcoin block 970086.
    const ROOT: &str = "c98d35d73e7fa56b942c55806c44431a8c1e6c3f6d601cbb146196df9cabbd6f";
    const RECEIPT: &str = "f008339cc0b9ae7defb608f010c4c97fe1ba91229a8d850ed585b345f308f120b3ad04d567b68ec72986969939f133d6eaa3a25a526e9dd3142f503e554024c508f120727250b9b98a9412343a130b45639b265ab40dbea1a19eee2e721b917066495f08f1046ac4156bf008869dc9b05c0fe1cb0083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267";
    const UPGRADE: &str = "08f020500b5404ebd52a82a664ff99db1bd2fbddd53675b47a41f360881889f0d685b808f020751378ec18a4c96be596b66bfe88c7ac17f0f33c601727b6659b7fc35b7431ad08f120b173f5dca748b196d2fcbce791743ba7d96dd8c0a8d020ecb6ddf221ab9a4ceb08f0208bbf167a1d9137448170b14dd4acd44abd3704a47d082c47d00a3c7cace18e2508f020d212a1341635bbf265e0b3536d0509772fa6a246670e4ad3559dfc111233ad4808f1207320ea449f681837c561fab404d7ccb21cac7c690e4481d987a108dfd2964c0808f020258bdb53ef33750744e9bfd2124b0899a54c1a8abcfa5a46d01cae79c9ee13cb08f02081ebc80aff1e45243658d85268c53c856654416f327d098dc041a3b11c67ce7b08f020e30ca2fa37b5b4ead54a12c80425699a890a337bbc61563d8953b8284c32c37f08f0200ffa559c05228d883b9e1c56865c4e5c8eea09a2976a2f0333651f9d0805c8f808f020b51173945e26e37e00da13414d22b7c8163bcf30ceeb5fbcb3e36b59bd1379d408f1590100000001b156cf4deefb54d9de31a79de473d89ef85d7c1ceb3d033c4d98e795139ac5ae0000000000feffffff02fe0600000000000016001429bf94177f88a8f7d87e808f945baf5ab222c80d0000000000000000226a20f00465cd0e000808f02059dbddfda6cff973c64c6356c2edccdb5e98c7b4af48f6537245b5c4de20aeef0808f1200856e0021c285f6f77abb195adf70a70679aa577eb626fc952710bd0fdd167640808f020ee52cea2bcef52150a9fe26331b1cc9be5057ec14904b3a4a8b3cfe000458e6d0808f120394537521b3b2d731b72c3ed84bd693a08da86318a2c83ebd3cdae204d187dde0808f1209e41ff1afcfa51602a1e6abf33c802fe265c05bae2363d06d0e7423724a76f430808f020e8bc6306f14fa6c9eee0d57cc748b2b5c3fd02144856e104aab12c1e66b476510808f020aa24e2789b30ba417b885d46626775b83e7418a4ea8ce3f38bb3bf5e0fc772d80808f1201b81f025881e936a826e504661ecf04589cb21a23cb91ee8dbb326eb62255c7e0808f020ba5d5a0cf2fc6696021ebe42e5252921c139dffda7509db3a0355b73bf2409790808f020cefbec33f7578c7fc953984f4ae8d062035ec22838f10abbe5886ee957b890650808f0208d1cdf277f547492b6fedceab5c25c32e3c6d9160b7e4c708537c0c594b088300808f120c572e7c7e193c04f14206d5151b8feec0b8f04564ea5b8091b56a03b29d5be9f0808f0209329ed9c5a05f8f88104da57550fb7d39bd54fa4259309258033dc4e91beaa0d0808000588960d73d7190103e69a3b";

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn pending_att(uri: &str) -> Vec<u8> {
        let mut payload = vec![uri.len() as u8];
        payload.extend_from_slice(uri.as_bytes());
        [
            vec![TAG_ATTESTATION],
            PENDING_TAG.to_vec(),
            vec![payload.len() as u8],
            payload,
        ]
        .concat()
    }

    fn bitcoin_att(height: u8) -> Vec<u8> {
        [vec![TAG_ATTESTATION], BITCOIN_TAG.to_vec(), vec![1, height]].concat()
    }

    #[test]
    fn finds_the_pending_attestation_in_a_real_receipt() {
        let scan = scan(&h(RECEIPT), &h(ROOT)).unwrap();
        assert!(scan.bitcoin_heights.is_empty());
        assert_eq!(scan.pending.len(), 1);
        let p = &scan.pending[0];
        assert_eq!(p.uri, "https://alice.btc.calendar.opentimestamps.org");
        assert_eq!(hex::encode(&p.commitment), "6ac4156b453bc7320cd5d54931f5dfc41bcc1703151e84fb42d601cb0662e7fb9fe78a61869dc9b05c0fe1cb");
        assert_eq!(
            upgrade_url(p).unwrap(),
            "https://alice.btc.calendar.opentimestamps.org/timestamp/6ac4156b453bc7320cd5d54931f5dfc41bcc1703151e84fb42d601cb0662e7fb9fe78a61869dc9b05c0fe1cb"
        );
    }

    #[test]
    fn splicing_the_real_upgrade_reaches_bitcoin_block_970086() {
        let receipt = h(RECEIPT);
        let pending = scan(&receipt, &h(ROOT)).unwrap().pending.remove(0);
        let complete = splice(&receipt, &h(ROOT), &pending, &h(UPGRADE)).unwrap();
        let check = scan(&complete, &h(ROOT)).unwrap();
        assert_eq!(check.bitcoin_heights, vec![970086]);
        assert!(check.pending.is_empty());
    }

    #[test]
    fn splices_into_a_non_final_slot_with_fork_markers() {
        // Node with two pending attestations; replace the first (fork-prefixed)
        // with a two-child upgrade. The second pending must survive intact.
        let digest = [7u8; 32];
        let receipt = [
            vec![TAG_FORK],
            pending_att("https://alice.btc.calendar.opentimestamps.org"),
            pending_att("https://bob.btc.calendar.opentimestamps.org"),
        ]
        .concat();
        let found = scan(&receipt, &digest).unwrap();
        assert_eq!(found.pending.len(), 2);
        let upgrade = [vec![TAG_FORK], bitcoin_att(5), bitcoin_att(6)].concat();
        let complete = splice(&receipt, &digest, &found.pending[0], &upgrade).unwrap();
        let check = scan(&complete, &digest).unwrap();
        assert_eq!(check.bitcoin_heights, vec![5, 6]);
        assert_eq!(check.pending.len(), 1);
        assert_eq!(
            check.pending[0].uri,
            "https://bob.btc.calendar.opentimestamps.org"
        );
    }

    #[test]
    fn splices_a_multi_child_upgrade_into_a_final_slot() {
        let digest = [9u8; 32];
        let receipt = [
            vec![OP_SHA256],
            pending_att("https://alice.btc.calendar.opentimestamps.org"),
        ]
        .concat();
        let pending = scan(&receipt, &digest).unwrap().pending.remove(0);
        let upgrade = [
            vec![TAG_FORK],
            bitcoin_att(1),
            vec![OP_APPEND, 1, 0xaa],
            bitcoin_att(2),
        ]
        .concat();
        let check = scan(
            &splice(&receipt, &digest, &pending, &upgrade).unwrap(),
            &digest,
        )
        .unwrap();
        assert_eq!(check.bitcoin_heights, vec![1, 2]);
    }

    #[test]
    fn refuses_an_upgrade_without_bitcoin() {
        let receipt = h(RECEIPT);
        let pending = scan(&receipt, &h(ROOT)).unwrap().pending.remove(0);
        let still_pending = pending_att("https://alice.btc.calendar.opentimestamps.org");
        assert!(splice(&receipt, &h(ROOT), &pending, &still_pending)
            .unwrap_err()
            .contains("no Bitcoin"));
    }

    #[test]
    fn rejects_malformed_timestamps() {
        let root = h(ROOT);
        let receipt = h(RECEIPT);
        assert!(
            scan(&receipt[..receipt.len() - 3], &root).is_err(),
            "truncated"
        );
        assert!(
            scan(&[receipt.clone(), vec![0]].concat(), &root).is_err(),
            "trailing bytes"
        );
        assert!(
            scan(&[0x02, 0x00], &root)
                .unwrap_err()
                .contains("unsupported"),
            "sha1 op"
        );
        assert!(
            scan(&vec![OP_SHA256; MAX_DEPTH + 2], &root).is_err(),
            "too deep"
        );
    }

    #[test]
    fn only_allowlisted_calendars_get_an_upgrade_url() {
        let mut p = scan(&h(RECEIPT), &h(ROOT)).unwrap().pending.remove(0);
        for bad in [
            "http://alice.btc.calendar.opentimestamps.org",
            "https://evil.example",
            "https://alice.btc.calendar.opentimestamps.org.evil.example",
            "https://169.254.169.254",
        ] {
            p.uri = bad.into();
            assert_eq!(upgrade_url(&p), None, "{bad}");
        }
    }
}
