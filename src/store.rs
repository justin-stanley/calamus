//! Storage seams: what calamus needs persisted, as traits the caller
//! implements over its own storage.
//!
//! calamus has no persistence of its own. FeatherReader implements these over
//! SQLite; [`memory`] has in-process implementations for tests and for a
//! single-process caller.
//!
//! The traits use `async fn`-in-trait with the `Send` bound spelled out on the
//! returned future (like [`crate::resolve::DnsResolver`]), so a caller can spawn
//! any calamus future on a multi-threaded runtime.

use std::future::Future;

use anyhow::Result;

/// The latest DPoP nonce each server origin handed out (RFC 9449 §8, §9).
///
/// [`crate::request::send_with_dpop`] reads the stored nonce before the first
/// attempt and stores every nonce a response offers, success or failure.
/// Keys are origins as [`crate::discovery::origin_of`] renders them
/// (`https://host[:port]`), never full URLs: the nonce belongs to the server, so
/// PAR and token on one issuer share it.
///
/// **Writes happen before any authentication**: PAR runs for whatever handle a
/// visitor typed, so the set of origins is attacker-influenced. An
/// implementation should expire entries that have not been touched for a while
/// (FeatherReader sweeps nonces untouched for longer than a fixed age; a stale
/// nonce is worthless anyway, since the server issues a fresh one with its next
/// challenge). `now` is passed to [`NonceStore::put`] for exactly that.
///
/// Ported from FeatherReader's `store::{get_nonce, put_nonce}`.
pub trait NonceStore: Send + Sync {
    /// The stored nonce for `origin`, if any.
    fn get(&self, origin: &str) -> impl Future<Output = Result<Option<String>>> + Send;

    /// Record `nonce` as the latest for `origin`, replacing any earlier one
    /// (servers rotate nonces). `now` is the write time in Unix seconds, for an
    /// implementation's expiry.
    fn put(&self, origin: &str, nonce: &str, now: i64) -> impl Future<Output = Result<()>> + Send;
}

/// In-process stores: a `Mutex<HashMap>` each.
///
/// For tests, and for a caller with one process and no need for its state to
/// survive a restart.
pub mod memory {
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use anyhow::Result;

    use super::NonceStore;

    /// [`NonceStore`] in memory.
    ///
    /// Unbounded by itself, and its writes are pre-authentication (see
    /// [`NonceStore`]): a long-running caller should call
    /// [`MemoryNonces::sweep`] periodically.
    #[derive(Debug, Default)]
    pub struct MemoryNonces {
        /// origin -> (nonce, when it was last written).
        nonces: Mutex<HashMap<String, (String, i64)>>,
    }

    impl MemoryNonces {
        /// An empty store.
        pub fn new() -> Self {
            Self::default()
        }

        /// Drop every nonce last written at or before `cutoff` (Unix seconds).
        /// Returns how many went. FeatherReader's `store::sweep_stale_nonces`.
        pub fn sweep(&self, cutoff: i64) -> usize {
            let mut nonces = self.lock();
            let before = nonces.len();
            nonces.retain(|_, (_, updated_at)| *updated_at > cutoff);
            before - nonces.len()
        }

        /// A panic elsewhere while holding the lock cannot leave a half-written
        /// entry (every write is one `insert`), so a poisoned lock is still a
        /// consistent map.
        fn lock(&self) -> MutexGuard<'_, HashMap<String, (String, i64)>> {
            self.nonces.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl NonceStore for MemoryNonces {
        async fn get(&self, origin: &str) -> Result<Option<String>> {
            Ok(self.lock().get(origin).map(|(nonce, _)| nonce.clone()))
        }

        async fn put(&self, origin: &str, nonce: &str, now: i64) -> Result<()> {
            self.lock()
                .insert(origin.to_string(), (nonce.to_string(), now));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory::MemoryNonces;
    use super::*;

    const NOW: i64 = 1_700_000_000;

    /// FeatherReader's `store::tests::nonces_are_stored_and_replaced_per_origin`,
    /// against the in-memory store: absent until put, one value per origin, and
    /// a later value replaces the earlier (servers rotate nonces).
    #[tokio::test]
    async fn memory_nonces_round_trip_per_origin_and_replace() -> anyhow::Result<()> {
        let nonces = MemoryNonces::new();
        assert_eq!(nonces.get("https://a.example").await?, None);

        nonces.put("https://a.example", "n1", NOW).await?;
        nonces.put("https://b.example", "n2", NOW).await?;
        assert_eq!(
            nonces.get("https://a.example").await?.as_deref(),
            Some("n1")
        );
        assert_eq!(
            nonces.get("https://b.example").await?.as_deref(),
            Some("n2")
        );

        // Rotation: servers rotate nonces, so a later value replaces the earlier.
        nonces.put("https://a.example", "n3", NOW).await?;
        assert_eq!(
            nonces.get("https://a.example").await?.as_deref(),
            Some("n3")
        );
        assert_eq!(
            nonces.get("https://b.example").await?.as_deref(),
            Some("n2"),
            "replacing one origin's nonce touched another's"
        );
        Ok(())
    }

    /// The sweep drops exactly the nonces untouched since the cutoff (inclusive,
    /// like FeatherReader's `sweep_stale_nonces`), and a `put` refreshes the age.
    #[tokio::test]
    async fn memory_nonces_sweep_only_what_is_stale() -> anyhow::Result<()> {
        let nonces = MemoryNonces::new();
        nonces.put("https://old.example", "o", NOW - 600).await?;
        nonces.put("https://edge.example", "e", NOW - 300).await?;
        nonces.put("https://new.example", "n", NOW).await?;
        nonces.put("https://moved.example", "m1", NOW - 900).await?;
        nonces.put("https://moved.example", "m2", NOW - 10).await?;

        assert_eq!(nonces.sweep(NOW - 300), 2);
        assert_eq!(nonces.get("https://old.example").await?, None);
        assert_eq!(nonces.get("https://edge.example").await?, None);
        assert_eq!(
            nonces.get("https://new.example").await?.as_deref(),
            Some("n")
        );
        assert_eq!(
            nonces.get("https://moved.example").await?.as_deref(),
            Some("m2")
        );
        Ok(())
    }

    /// Every future the seam returns is `Send`, so a caller can spawn it on a
    /// multi-threaded runtime. Compile-time: nothing here is awaited.
    #[test]
    fn the_nonce_store_seam_and_its_futures_are_send() {
        fn assert_send<T: Send>(_: &T) {}
        fn generic<N: NonceStore>(nonces: &N) {
            assert_send(&nonces.get("https://a.example"));
            assert_send(&nonces.put("https://a.example", "n", NOW));
        }
        let nonces = MemoryNonces::new();
        generic(&nonces);
        assert_send(&nonces);
    }
}
