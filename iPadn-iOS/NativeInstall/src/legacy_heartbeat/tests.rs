use super::*;
use crate::test_wire::{message, Wire};
use idevice::Idevice;
use tokio::time::timeout;

fn endpoints() -> (HeartbeatClient, Idevice) {
    let (client, peer) = tokio::io::duplex(4096);
    (HeartbeatClient::new(Idevice::new(Box::new(client), "test")), Idevice::new(Box::new(peer), "peer"))
}
fn logs() -> Arc<Mutex<Vec<String>>> { Arc::new(Mutex::new(Vec::new())) }
async fn marco_polo(peer: &mut Idevice, interval: u64) {
    peer.send_message(message!({"Command": "Marco", "Interval": interval})).await.unwrap();
    let reply = timeout(Duration::from_secs(1), peer.read_message()).await.unwrap().unwrap();
    assert_eq!(reply.get("Command").and_then(plist::Value::as_string), Some("Polo"));
}
async fn closed(peer: &mut Idevice) {
    assert_eq!(timeout(Duration::from_secs(1), peer.read_any(1)).await.unwrap().unwrap().len(), 0);
}

#[tokio::test]
async fn first_polo_is_required_for_readiness_and_later_polo_is_sent() {
    let (client, mut peer) = endpoints();
    let logs = logs();
    let mut startup = Box::pin(LegacyHeartbeat::start(client, logs.clone()));
    assert!(timeout(Duration::from_millis(20), &mut startup).await.is_err());
    assert!(!logs.lock().unwrap().iter().any(|s| s.contains("step=ready")));
    let (guard, ()) = tokio::join!(startup, marco_polo(&mut peer, 15));
    let guard = guard.unwrap_or_else(|e| panic!("{}", e.stage));
    for interval in [1, u64::MAX] { marco_polo(&mut peer, interval).await; }
    guard.check().unwrap_or_else(|e| panic!("{}", e.stage));
    guard.stop().await;
    closed(&mut peer).await;
    assert!(logs.lock().unwrap().iter().any(|s| s == "phase=heartbeat step=stopped"));
}

#[tokio::test]
async fn failed_or_cancelled_startup_closes_socket_and_redacts_peer_values() {
    for message in [
        message!({"Command": "SleepyTime"}),
        message!({"Command": "SENSITIVE_COMMAND"}),
        message!({"Interval": "SENSITIVE_INTERVAL"}),
        message!({"Interval": -1}),
        message!({"SENSITIVE_KEY": "SENSITIVE_VALUE"}),
    ] {
        let (client, mut peer) = endpoints();
        let logs = logs();
        peer.send_message(message).await.unwrap();
        let error = LegacyHeartbeat::start(client, logs.clone()).await.err().unwrap();
        assert_eq!(error.stage, "heartbeat_setup");
        assert!(!error.message.contains("SENSITIVE"));
        assert!(!logs.lock().unwrap().join("\n").contains("SENSITIVE"));
        closed(&mut peer).await;
    }
    let (client, mut peer) = endpoints();
    let mut startup = Box::pin(LegacyHeartbeat::start(client, logs()));
    assert!(timeout(Duration::from_millis(20), &mut startup).await.is_err());
    drop(startup);
    closed(&mut peer).await;
    let (client, peer) = endpoints();
    drop(peer);
    assert_eq!(LegacyHeartbeat::start(client, logs()).await.err().unwrap().stage, "heartbeat_setup");
}

#[tokio::test]
async fn guard_drop_aborts_task_instead_of_detaching_socket() {
    let (client, mut peer) = endpoints();
    let (guard, ()) = tokio::join!(LegacyHeartbeat::start(client, logs()), marco_polo(&mut peer, 15));
    drop(guard.unwrap_or_else(|e| panic!("{}", e.stage)));
    closed(&mut peer).await;
}

#[tokio::test]
async fn heartbeat_loss_blocks_new_work_and_interrupts_inflight_wait() {
    let (client, mut peer) = endpoints();
    let (guard, ()) = tokio::join!(LegacyHeartbeat::start(client, logs()), marco_polo(&mut peer, 15));
    let guard = guard.unwrap_or_else(|e| panic!("{}", e.stage));
    let work = async { std::future::pending::<()>().await; Ok(()) };
    let monitored = guard.guard(work);
    let (result, ()) = tokio::join!(monitored, async { drop(peer); });
    assert_eq!(result.err().unwrap().stage, "heartbeat_lost");
    let ran = std::cell::Cell::new(false);
    let error = guard.guard(async { ran.set(true); Ok(()) }).await.err().unwrap();
    assert_eq!(error.stage, "heartbeat_lost");
    assert!(!ran.get(), "no command may start after heartbeat loss");
}

#[test]
fn untrusted_interval_cannot_overflow_or_disable_timeout() {
    assert_eq!(next_timeout(0), 5);
    assert_eq!(next_timeout(15), 20);
    assert_eq!(next_timeout(u64::MAX), 60);
}
