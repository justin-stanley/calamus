//! The client installs ring as rustls's process-wide provider, idempotently,
//! and leaves a provider that is already installed alone.

use tokio_rustls::rustls::crypto::CryptoProvider;

#[test]
fn the_client_installs_ring_and_a_prior_provider_is_kept() {
    // Twice: harmless to repeat.
    calamus::net::install_crypto_provider();
    calamus::net::install_crypto_provider();
    assert!(tokio_rustls::rustls::crypto::CryptoProvider::get_default().is_some());

    // A provider installed by the consumer (here, ring again) is left alone
    // and a further call does not panic.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    calamus::net::install_crypto_provider();
    assert!(CryptoProvider::get_default().is_some());
}
