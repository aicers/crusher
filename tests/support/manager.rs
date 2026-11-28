//! Session API helpers shared by fake Managers.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use review_protocol::{
    auth::{AuthorizationContext, AuthorizerV2Adapter, NoopAuthorizer, PeerContext},
    session::{
        PendingSession, ProtocolWindow, ServerHandle, ServerIncoming, ServerListener,
        ServerListenerOptions, ServerTransportOptions, SessionError, SessionOptions,
    },
};

/// Binds a fake Manager with the legacy frame budgets and current protocol.
///
/// # Panics
/// Panics if the test address cannot be bound.
pub(crate) fn listener(tls: Arc<rustls::ServerConfig>, address: SocketAddr) -> ServerListener {
    ServerListener::bind(
        address,
        tls,
        ServerListenerOptions {
            transport: ServerTransportOptions::default(),
            session: SessionOptions::legacy_compatible(),
            protocol: ProtocolWindow::new(">=0", review_protocol::PROTOCOL_VERSION)
                .expect("valid test protocol window"),
            handshake_timeout: Duration::from_secs(5),
        },
    )
    .expect("bind fake Manager")
}

/// Admits a test client after checking its advertised metadata.
///
/// # Errors
/// Returns a session error if the handshake fails.
///
/// # Panics
/// Panics if the client advertises unexpected metadata.
pub(crate) async fn accept(
    pending: PendingSession,
) -> Result<(ServerHandle, ServerIncoming), SessionError> {
    let session = pending.handshake().await?;
    let claims = session.agent_claims();
    assert_eq!(claims.agent_name, "crusher");
    assert_eq!(claims.agent_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(claims.protocol_version, review_protocol::PROTOCOL_VERSION);
    assert!(claims.capabilities.is_empty());
    assert!(claims.active_trust_epoch.is_none());
    assert!(claims.manifest_formats.is_none());
    assert!(claims.provisioning_fingerprint.is_none());
    assert!(claims.audit_health.is_none());
    Ok(session.admit(
        AuthorizationContext::from_peer_context(&PeerContext::new("test")),
        Arc::new(AuthorizerV2Adapter::new(NoopAuthorizer)),
    ))
}
