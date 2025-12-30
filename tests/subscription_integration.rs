//! Integration tests for the subscription pipeline.
//!
//! These tests verify stream lifecycle management (open/close on policy
//! add/delete), notify flow, and timestamp cleanup when policies are deleted.
//!
//! Run these tests with:
//! ```bash
//! cargo test --features integration-tests
//! ```

#![cfg(all(test, feature = "integration-tests"))]

mod support;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use review_protocol::types::{SamplingKind, SamplingPolicy};
use support::fake_giganto::{
    FakeGigantoServer, StreamEvent, TEST_INGEST_PORT_BASE, TEST_PUBLISH_PORT_BASE,
};
use tempfile::NamedTempFile;
use tokio::{
    sync::{Notify, RwLock},
    time::timeout,
};

const TIMEOUT_SECS: u64 = 10;
const SECS_PER_MINUTE: u64 = 60;
const SECS_PER_DAY: u64 = 86_400;

fn test_policy(id: u32) -> SamplingPolicy {
    SamplingPolicy {
        id,
        kind: SamplingKind::Conn,
        interval: Duration::from_secs(15 * SECS_PER_MINUTE),
        period: Duration::from_secs(SECS_PER_DAY),
        offset: 32_400,
        src_ip: None,
        dst_ip: None,
        node: Some("test_node".to_string()),
        column: None,
    }
}

/// Test: When a policy is added, a stream should be opened.
/// When the policy is deleted, the stream should be closed.
#[tokio::test]
async fn stream_lifecycle_on_policy_add_delete() {
    // Each test uses unique ports to avoid conflicts
    let port_offset = 0;
    let ingest_port = TEST_INGEST_PORT_BASE + port_offset;
    let publish_port = TEST_PUBLISH_PORT_BASE + port_offset;

    // Create a temporary file for timestamp data
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let last_series_time_path = temp_file.path().to_path_buf();

    // Initialize the timestamp file with empty JSON object
    std::fs::write(&last_series_time_path, "{}").expect("Failed to write timestamp file");

    // Start the fake Giganto server
    let server = FakeGigantoServer::new(ingest_port, publish_port);
    let stream_events = server.stream_events();
    let shutdown = Arc::new(Notify::new());
    let server_shutdown = shutdown.clone();

    let server_handle = tokio::spawn(async move {
        server.run(server_shutdown).await;
    });

    // Give the server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create the subscription client
    let (request_send, request_recv) = async_channel::bounded(10);
    let active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let delete_policy_ids: Arc<RwLock<Vec<u32>>> = Arc::new(RwLock::new(Vec::new()));

    let ingest_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), ingest_port);
    let publish_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), publish_port);

    let certs = load_test_certs();
    let client = crusher::subscribe::Client::new(
        ingest_addr,
        publish_addr,
        "localhost".to_string(),
        last_series_time_path.clone(),
        &certs,
        request_recv,
    );

    let client_shutdown = Arc::new(Notify::new());
    let client_shutdown_clone = client_shutdown.clone();
    let active_policy_list_clone = active_policy_list.clone();
    let delete_policy_ids_clone = delete_policy_ids.clone();

    let client_handle = tokio::spawn(async move {
        let _ = client
            .run(
                active_policy_list_clone,
                delete_policy_ids_clone,
                client_shutdown_clone,
            )
            .await;
    });

    // Give the client time to connect
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Add a policy - this should trigger a stream open
    let policy = test_policy(1);
    active_policy_list
        .write()
        .await
        .insert(policy.id, policy.clone());
    request_send
        .send(policy.clone())
        .await
        .expect("Failed to send policy");

    // Wait for stream open event
    let stream_open = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let events = stream_events.read().await;
            if events.iter().any(|e| matches!(e, StreamEvent::Opened(1))) {
                return true;
            }
            drop(events);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    assert!(
        stream_open.is_ok(),
        "Timed out waiting for stream open event"
    );

    // Delete the policy - this should trigger stream close
    active_policy_list.write().await.remove(&1);
    delete_policy_ids.write().await.push(1);

    // Wait for stream close event
    let stream_close = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let events = stream_events.read().await;
            if events.iter().any(|e| matches!(e, StreamEvent::Closed(1))) {
                return true;
            }
            drop(events);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    assert!(
        stream_close.is_ok(),
        "Timed out waiting for stream close event"
    );

    // Cleanup
    client_shutdown.notify_one();
    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

/// Test: Adding multiple policies should open multiple streams.
#[tokio::test]
async fn multiple_policy_streams() {
    let port_offset = 2;
    let ingest_port = TEST_INGEST_PORT_BASE + port_offset;
    let publish_port = TEST_PUBLISH_PORT_BASE + port_offset;

    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let last_series_time_path = temp_file.path().to_path_buf();
    std::fs::write(&last_series_time_path, "{}").expect("Failed to write timestamp file");

    let server = FakeGigantoServer::new(ingest_port, publish_port);
    let stream_events = server.stream_events();
    let shutdown = Arc::new(Notify::new());
    let server_shutdown = shutdown.clone();

    let server_handle = tokio::spawn(async move {
        server.run(server_shutdown).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let (request_send, request_recv) = async_channel::bounded(10);
    let active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let delete_policy_ids: Arc<RwLock<Vec<u32>>> = Arc::new(RwLock::new(Vec::new()));

    let ingest_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), ingest_port);
    let publish_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), publish_port);

    let certs = load_test_certs();
    let client = crusher::subscribe::Client::new(
        ingest_addr,
        publish_addr,
        "localhost".to_string(),
        last_series_time_path.clone(),
        &certs,
        request_recv,
    );

    let client_shutdown = Arc::new(Notify::new());
    let client_shutdown_clone = client_shutdown.clone();
    let active_policy_list_clone = active_policy_list.clone();
    let delete_policy_ids_clone = delete_policy_ids.clone();

    let client_handle = tokio::spawn(async move {
        let _ = client
            .run(
                active_policy_list_clone,
                delete_policy_ids_clone,
                client_shutdown_clone,
            )
            .await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Add multiple policies
    for id in 1..=3 {
        let policy = test_policy(id);
        active_policy_list
            .write()
            .await
            .insert(policy.id, policy.clone());
        request_send
            .send(policy)
            .await
            .expect("Failed to send policy");
    }

    // Wait for all stream open events
    let all_opened = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let events = stream_events.read().await;
            let opened_count = events
                .iter()
                .filter(|e| matches!(e, StreamEvent::Opened(_)))
                .count();
            if opened_count >= 3 {
                return true;
            }
            drop(events);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    assert!(
        all_opened.is_ok(),
        "Timed out waiting for all streams to open"
    );

    // Verify we have 3 distinct stream open events
    let events = stream_events.read().await;
    let opened_ids: Vec<u32> = events
        .iter()
        .filter_map(|e| {
            if let StreamEvent::Opened(id) = e {
                Some(*id)
            } else {
                None
            }
        })
        .collect();
    assert!(opened_ids.contains(&1));
    assert!(opened_ids.contains(&2));
    assert!(opened_ids.contains(&3));

    // Cleanup
    client_shutdown.notify_one();
    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

/// Test: `delete_policy_ids` triggers timestamp cleanup for deleted policies.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn delete_policy_triggers_timestamp_cleanup() {
    let port_offset = 4;
    let ingest_port = TEST_INGEST_PORT_BASE + port_offset;
    let publish_port = TEST_PUBLISH_PORT_BASE + port_offset;

    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let last_series_time_path = temp_file.path().to_path_buf();

    // Initialize timestamp file with policy ID 1's timestamp
    #[allow(clippy::unreadable_literal)]
    let initial_timestamps = serde_json::json!({
        "1": 1668643200000000000_i64,
        "2": 1668729600000000000_i64
    });
    std::fs::write(
        &last_series_time_path,
        serde_json::to_string(&initial_timestamps).expect("serialize"),
    )
    .expect("Failed to write timestamp file");

    let server = FakeGigantoServer::new(ingest_port, publish_port);
    let stream_events = server.stream_events();
    let shutdown = Arc::new(Notify::new());
    let server_shutdown = shutdown.clone();

    let server_handle = tokio::spawn(async move {
        server.run(server_shutdown).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Read the initial timestamp file to ensure policy 1 exists
    crusher::subscribe::read_last_timestamp(&last_series_time_path)
        .await
        .expect("Failed to read timestamp");

    let (request_send, request_recv) = async_channel::bounded(10);
    let active_policy_list: Arc<RwLock<HashMap<u32, SamplingPolicy>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let delete_policy_ids: Arc<RwLock<Vec<u32>>> = Arc::new(RwLock::new(Vec::new()));

    let ingest_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), ingest_port);
    let publish_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), publish_port);

    let certs = load_test_certs();
    let client = crusher::subscribe::Client::new(
        ingest_addr,
        publish_addr,
        "localhost".to_string(),
        last_series_time_path.clone(),
        &certs,
        request_recv,
    );

    let client_shutdown = Arc::new(Notify::new());
    let client_shutdown_clone = client_shutdown.clone();
    let active_policy_list_clone = active_policy_list.clone();
    let delete_policy_ids_clone = delete_policy_ids.clone();

    let client_handle = tokio::spawn(async move {
        let _ = client
            .run(
                active_policy_list_clone,
                delete_policy_ids_clone,
                client_shutdown_clone,
            )
            .await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Add policy 1
    let policy = test_policy(1);
    active_policy_list
        .write()
        .await
        .insert(policy.id, policy.clone());
    request_send
        .send(policy.clone())
        .await
        .expect("Failed to send policy");

    // Wait for stream open
    let stream_open = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            let events = stream_events.read().await;
            if events.iter().any(|e| matches!(e, StreamEvent::Opened(1))) {
                return true;
            }
            drop(events);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(stream_open.is_ok(), "Stream should open for policy 1");

    // Delete policy 1 - this should trigger timestamp cleanup
    active_policy_list.write().await.remove(&1);
    delete_policy_ids.write().await.push(1);

    // Wait for stream close and timestamp cleanup
    let cleanup_complete = timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            // Check if stream was closed
            let events = stream_events.read().await;
            let stream_closed = events.iter().any(|e| matches!(e, StreamEvent::Closed(1)));
            drop(events);

            if stream_closed {
                // Check if timestamp was cleaned up
                let content = std::fs::read_to_string(&last_series_time_path).unwrap_or_default();
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content)
                    && json.get("1").is_none()
                {
                    return true;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    assert!(
        cleanup_complete.is_ok(),
        "Timestamp cleanup should complete for deleted policy"
    );

    // Verify policy 2's timestamp is still present
    let content = std::fs::read_to_string(&last_series_time_path).expect("read file");
    let json: serde_json::Value = serde_json::from_str(&content).expect("parse json");
    assert!(
        json.get("2").is_some(),
        "Policy 2's timestamp should still exist"
    );

    // Cleanup
    client_shutdown.notify_one();
    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(2), client_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

fn load_test_certs() -> crusher::client::Certs {
    use std::fs;

    let cert_pem = fs::read("tests/cert.pem").expect("Failed to read cert.pem");
    let key_pem = fs::read("tests/key.pem").expect("Failed to read key.pem");
    let ca_cert_pem = fs::read("tests/ca_cert.pem").expect("Failed to read ca_cert.pem");

    let certs = crusher::client::Certs::to_cert_chain(&cert_pem).expect("parse cert");
    let key = crusher::client::Certs::to_private_key(&key_pem).expect("parse key");
    let ca_certs = crusher::client::Certs::to_ca_certs(&[&ca_cert_pem]).expect("parse ca");

    crusher::client::Certs {
        certs,
        key,
        ca_certs,
    }
}
