//! Own the network heartbeat for the lifetime of one legacy operation.
//! No independent provider/lockdown connection: the caller supplies a service
//! opened by its existing authenticated, route-bound legacy session.
use std::{future::Future, sync::{Arc, Mutex}, time::Duration};
use idevice::{heartbeat::HeartbeatClient, HeartbeatError, IdeviceError};
use tokio::{sync::watch, task::JoinHandle};
use crate::{Failure, failure};

pub(crate) struct LegacyHeartbeat {
    task: JoinHandle<()>,
    alive: watch::Receiver<bool>,
    diagnostics: Arc<Mutex<Vec<String>>>,
}

fn record(diagnostics: &Arc<Mutex<Vec<String>>>, entry: impl Into<String>) {
    if let Ok(mut entries) = diagnostics.lock() { entries.push(entry.into()); }
}

fn code(error: &IdeviceError) -> &'static str {
    match error {
        IdeviceError::Heartbeat(HeartbeatError::SleepyTime) => "sleep",
        IdeviceError::Heartbeat(HeartbeatError::Timeout) | IdeviceError::Timeout => "timed_out",
        IdeviceError::Socket(_) => "socket",
        IdeviceError::Rustls(_) => "tls",
        _ => "invalid_message",
    }
}

fn next_timeout(interval: u64) -> u64 { interval.saturating_add(5).clamp(5, 60) }

async fn exchange(client: &mut HeartbeatClient, timeout: u64) -> Result<u64, IdeviceError> {
    let interval = client.get_marco(timeout).await?;
    // Bound writes too; a blackholed socket must not leave an apparently live
    // task indefinitely. Never log the device's plist or raw error text.
    tokio::time::timeout(Duration::from_secs(5), client.send_polo()).await
        .map_err(|_| IdeviceError::Timeout)??;
    Ok(interval)
}

impl LegacyHeartbeat {
    pub(crate) async fn start(mut client: HeartbeatClient, diagnostics: Arc<Mutex<Vec<String>>>)
        -> Result<Self, Failure>
    {
        record(&diagnostics, "phase=heartbeat step=wait_first");
        let mut interval = exchange(&mut client, 15).await.map_err(|error| {
            record(&diagnostics, format!("phase=heartbeat result=failed code={}", code(&error)));
            failure("heartbeat_setup", "legacy heartbeat initial exchange failed")
        })?;
        record(&diagnostics, "phase=heartbeat step=ready polo=1");
        let (sender, alive) = watch::channel(true);
        let logs = diagnostics.clone();
        let task = tokio::spawn(async move {
            let mut count = 1;
            loop {
                match exchange(&mut client, next_timeout(interval)).await {
                    Ok(next) => {
                        interval = next;
                        count += 1;
                        // Enough to confirm ongoing liveness without unbounded
                        // periodic logs during long installations.
                        if count <= 3 { record(&logs, format!("phase=heartbeat step=polo count={count}")); }
                    }
                    Err(error) => {
                        record(&logs, format!("phase=heartbeat result=lost code={}", code(&error)));
                        let _ = sender.send(false);
                        break;
                    }
                }
            }
        });
        Ok(Self { task, alive, diagnostics })
    }

    pub(crate) fn check(&self) -> Result<(), Failure> {
        if !*self.alive.borrow() || self.task.is_finished() {
            Err(failure("heartbeat_lost", "legacy heartbeat ended; check inventory before retrying installation"))
        } else { Ok(()) }
    }

    pub(crate) async fn guard<T>(&self, work: impl Future<Output = Result<T, Failure>>)
        -> Result<T, Failure>
    {
        self.check()?;
        let mut alive = self.alive.clone();
        tokio::select! {
            biased;
            _ = alive.changed() => Err(failure("heartbeat_lost",
                "legacy heartbeat ended; check inventory before retrying installation")),
            result = work => { self.check()?; result }
        }
    }

    pub(crate) async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
        record(&self.diagnostics, "phase=heartbeat step=stopped");
    }
}

impl Drop for LegacyHeartbeat {
    fn drop(&mut self) {
        // JoinHandle's normal Drop detaches. Abort also covers failed service
        // setup, cancellation, unwinding and dropping the entire operation.
        self.task.abort();
    }
}

#[cfg(test)]
mod tests;
