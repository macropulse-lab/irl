//! T-2.2 — in-memory per-agent exposure tracker (foundation).
//!
//! # What this is
//! A lock-free-per-agent replacement for the `pg_advisory_xact_lock` +
//! `SUM(execution_notional) WHERE status='PENDING'` check in
//! [`crate::db::insert_trace_atomic`]. That DB lock serializes every
//! non-reduce-only authorize for an agent across a full transaction (~ms). This
//! tracker moves the cap decision to an in-memory per-agent counter: concurrent
//! authorizes for the *same* agent serialize only on a DashMap shard lock (~ns),
//! while different agents proceed fully in parallel.
//!
//! # What this is NOT (yet)
//! This module is **not wired into authorize enforcement**. The cap enforced by
//! the DB path is on *summed PENDING notional*, so a correct in-memory cutover
//! must also decrement this counter on every PENDING→non-PENDING transition —
//! i.e. on bind ([`crate::routes::bind`]) and on expiry
//! ([`crate::verifier`]) — and mirror how HALTED traces are recorded. Those
//! decrement paths span multiple modules and cannot be integration-tested
//! without a live DB, and the cap is a financial control, so the cutover is
//! deferred to a DB-tested follow-up. This file lands and proves the hard,
//! correctness-critical core (the concurrent counter) in isolation.

use dashmap::DashMap;
use uuid::Uuid;

/// Rejected reservation: the agent's proposed pending notional would exceed cap.
#[derive(Debug, Clone, PartialEq)]
pub struct CapExceeded {
    /// The would-be total pending notional (current reserved + requested).
    pub attempted: f64,
    /// The effective cap (agent cap × regime scale) that was exceeded.
    pub cap: f64,
}

/// Per-agent reserved (pending) notional. Thread-safe; per-agent atomic.
#[derive(Default)]
pub struct ExposureTracker {
    reserved: DashMap<Uuid, f64>,
}

impl ExposureTracker {
    pub fn new() -> Self {
        Self {
            reserved: DashMap::new(),
        }
    }

    /// Hydrate the tracker from the DB at boot: `(agent_id, pending_notional)`
    /// pairs, typically
    /// `SELECT agent_id, SUM(execution_notional) ... WHERE status='PENDING' GROUP BY agent_id`.
    pub fn hydrate(rows: impl IntoIterator<Item = (Uuid, f64)>) -> Self {
        let reserved = DashMap::new();
        for (agent, notional) in rows {
            reserved.insert(agent, notional.max(0.0));
        }
        Self { reserved }
    }

    /// Current reserved (pending) notional for an agent.
    pub fn current(&self, agent: Uuid) -> f64 {
        self.reserved.get(&agent).map(|r| *r).unwrap_or(0.0)
    }

    /// Atomically reserve `notional` for `agent` against `cap`.
    ///
    /// If `current + notional > cap`, nothing is reserved and `Err(CapExceeded)`
    /// is returned. Otherwise the agent's reserved total is increased by
    /// `notional` and the new total is returned. Atomic per agent: the DashMap
    /// entry lock is held for the read-check-write, so concurrent reservations
    /// for the same agent cannot both pass and breach the cap.
    pub fn try_reserve(&self, agent: Uuid, notional: f64, cap: f64) -> Result<f64, CapExceeded> {
        let mut entry = self.reserved.entry(agent).or_insert(0.0);
        let proposed = *entry + notional;
        if proposed > cap {
            return Err(CapExceeded {
                attempted: proposed,
                cap,
            });
        }
        *entry = proposed;
        Ok(proposed)
    }

    /// Release `notional` when a trace leaves PENDING (bound or expired).
    /// Clamps at zero so counter drift can never make exposure negative.
    pub fn release(&self, agent: Uuid, notional: f64) {
        if let Some(mut entry) = self.reserved.get_mut(&agent) {
            *entry = (*entry - notional).max(0.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn agent() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn reserve_within_cap_succeeds() {
        let t = ExposureTracker::new();
        let a = agent();
        assert_eq!(t.try_reserve(a, 100.0, 1000.0), Ok(100.0));
        assert_eq!(t.current(a), 100.0);
    }

    #[test]
    fn reserve_exceeding_cap_reserves_nothing() {
        let t = ExposureTracker::new();
        let a = agent();
        t.try_reserve(a, 900.0, 1000.0).unwrap();
        let err = t.try_reserve(a, 200.0, 1000.0).unwrap_err();
        assert_eq!(err.attempted, 1100.0);
        assert_eq!(err.cap, 1000.0);
        // Rejected reservation must not have consumed any headroom.
        assert_eq!(t.current(a), 900.0);
    }

    #[test]
    fn reservations_accumulate_up_to_cap() {
        let t = ExposureTracker::new();
        let a = agent();
        assert!(t.try_reserve(a, 400.0, 1000.0).is_ok());
        assert!(t.try_reserve(a, 400.0, 1000.0).is_ok());
        assert!(t.try_reserve(a, 400.0, 1000.0).is_err()); // 1200 > 1000
        assert_eq!(t.current(a), 800.0);
    }

    #[test]
    fn exactly_at_cap_is_allowed() {
        let t = ExposureTracker::new();
        let a = agent();
        assert_eq!(t.try_reserve(a, 1000.0, 1000.0), Ok(1000.0));
    }

    #[test]
    fn release_decrements_and_clamps_at_zero() {
        let t = ExposureTracker::new();
        let a = agent();
        t.try_reserve(a, 500.0, 1000.0).unwrap();
        t.release(a, 200.0);
        assert_eq!(t.current(a), 300.0);
        // Over-release cannot go negative.
        t.release(a, 999.0);
        assert_eq!(t.current(a), 0.0);
    }

    #[test]
    fn agents_are_independent() {
        let t = ExposureTracker::new();
        let (a, b) = (agent(), agent());
        t.try_reserve(a, 900.0, 1000.0).unwrap();
        // b starts fresh — its own cap headroom is untouched by a.
        assert!(t.try_reserve(b, 900.0, 1000.0).is_ok());
        assert_eq!(t.current(a), 900.0);
        assert_eq!(t.current(b), 900.0);
    }

    #[test]
    fn hydrate_seeds_pending_notional() {
        let a = agent();
        let t = ExposureTracker::hydrate([(a, 750.0)]);
        assert_eq!(t.current(a), 750.0);
        // Only 250 headroom remains against a 1000 cap.
        assert!(t.try_reserve(a, 300.0, 1000.0).is_err());
        assert!(t.try_reserve(a, 250.0, 1000.0).is_ok());
    }

    #[test]
    fn concurrent_reservations_never_breach_cap() {
        // 100 threads each try to reserve 1.0 against a cap of 40 for one agent.
        // Exactly 40 must succeed — proves the read-check-write is atomic and a
        // race cannot let two reservations both pass the boundary.
        let t = Arc::new(ExposureTracker::new());
        let a = agent();
        let cap = 40.0;
        let mut handles = Vec::new();
        for _ in 0..100 {
            let t = t.clone();
            handles.push(thread::spawn(move || t.try_reserve(a, 1.0, cap).is_ok()));
        }
        let successes = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&ok| ok)
            .count();
        assert_eq!(successes, 40, "exactly cap reservations may succeed");
        assert_eq!(t.current(a), 40.0);
    }
}
