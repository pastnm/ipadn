//! installation_proxy Lookup is a sequence of status/result plists. Preserve
//! the request and wait for completion rather than assuming the first frame
//! contains the inventory. Diagnostics contain only fixed categories/counts.
use idevice::{IdeviceError, installation_proxy::InstallationProxyClient};
use crate::{Failure, MAX_REPLY, failure, io_diagnostics};

const MAX_FRAMES: usize = 128;

/// Only legacy read-only Lookup can reconnect. Installation and Upgrade never
/// enter this module. The caller keeps its existing overall lookup timeout.
pub(crate) trait Service {
    async fn open(&mut self) -> Result<InstallationProxyClient, Failure>;
    fn record(&self, entry: String);
    fn allows_legacy_retry(&self) -> bool;
    async fn guard<T>(&self, work: impl std::future::Future<Output = Result<T, Failure>>) -> Result<T, Failure> {
        work.await
    }
}

struct Attempt {
    result: Result<plist::Dictionary, Failure>,
    first_header_eof: bool,
}

fn without_attributes(message: &plist::Value) -> Option<plist::Value> {
    let mut copy = message.clone();
    let dictionary = copy.as_dictionary_mut()?;
    if dictionary.get("Command")?.as_string()? != "Lookup" { return None; }
    dictionary.get_mut("ClientOptions")?.as_dictionary_mut()?.remove("ReturnAttributes")?;
    Some(copy)
}

pub(crate) async fn run_with_retry(service: &mut impl Service, message: &plist::Value)
    -> Result<plist::Dictionary, Failure>
{
    service.record("phase=app_query step=attempt attempt=1 framing=split attributes=requested".into());
    let mut client = service.open().await?;
    let first = service.guard(async {
        Ok(attempt(&mut client, message, &mut |entry| service.record(entry)).await)
    }).await?;
    // A closed service connection must never be reused for the retry.
    drop(client);
    if first.result.is_ok() || !first.first_header_eof || !service.allows_legacy_retry() {
        return first.result;
    }
    let Some(retry_message) = without_attributes(message) else { return first.result };
    service.record("phase=app_query step=retry attempt=2 reason=first_header_eof attributes=all".into());
    let mut client = service.open().await?;
    let second = service.guard(async {
        Ok(attempt(&mut client, &retry_message, &mut |entry| service.record(entry)).await)
    }).await?;
    let outcome = if second.result.is_ok() { "succeeded" } else { "failed" };
    service.record(format!("phase=app_query step=retry_result attempt=2 result={outcome}"));
    second.result
}

fn io_failure(error: IdeviceError) -> Failure {
    match error {
        IdeviceError::Socket(error) => failure("lookup", format!("code=query_socket {}",
            io_diagnostics::io_detail(&error))),
        IdeviceError::Rustls(error) => failure("lookup", format!("code=query_tls {}",
            io_diagnostics::idevice_detail(&IdeviceError::Rustls(error)))),
        IdeviceError::Timeout => failure("lookup", "code=query_timed_out"),
        _ => failure("lookup", "code=query_transport_error"),
    }
}

fn device_code(value: &plist::Value) -> &'static str {
    match value.as_string() {
        Some("DeviceLocked" | "PasswordProtected") => "query_device_locked",
        Some("LookupFailed" | "ApplicationLookupFailed") => "query_device_lookup_failed",
        Some("InvalidArgument" | "InvalidArguments" | "InvalidOptions") => "query_invalid_options",
        Some("InvalidCommand" | "UnknownCommand") => "query_invalid_command",
        Some("ServiceProhibited" | "GetProhibited" | "NotEntitled" | "PermissionDenied") => "query_access_denied",
        Some("SessionInactive" | "InvalidHostID") => "query_session_rejected",
        _ => "query_device_rejected",
    }
}

async fn run_inner(client: &mut InstallationProxyClient, message: &plist::Value,
    record: &mut impl FnMut(String), first_header_eof: &mut bool) -> Result<plist::Dictionary, Failure>
{
    let mut body = Vec::new();
    plist::to_writer_xml(&mut body, message).map_err(|_| failure("lookup", "code=query_encode_failed"))?;
    if body.len() > MAX_REPLY as usize { return Err(failure("lookup", "code=query_invalid_size")); }
    // Match idevice/property_list_service's separate header and payload writes.
    // send_raw also flushes each part. Do not rely on TCP packet boundaries.
    record("phase=app_query step=send framing=split".into());
    client.idevice.send_raw(&(body.len() as u32).to_be_bytes()).await.map_err(io_failure)?;
    client.idevice.send_raw(&body).await.map_err(io_failure)?;

    let mut result: Option<plist::Dictionary> = None;
    let mut total = 0u64;
    for index in 1..=MAX_FRAMES {
        record(format!("phase=app_query step=read_header frame={index}"));
        let mut header = [0u8; 4];
        let mut received = 0;
        while received < header.len() {
            let read = client.idevice.read_any((header.len() - received) as u32).await;
            let error = match read {
                Ok(bytes) if !bytes.is_empty() => {
                    header[received..received + bytes.len()].copy_from_slice(&bytes);
                    received += bytes.len();
                    continue;
                }
                Ok(_) => IdeviceError::Socket(std::io::ErrorKind::UnexpectedEof.into()),
                Err(error) => error,
            };
            if matches!(&error, IdeviceError::Socket(e) if e.kind() == std::io::ErrorKind::UnexpectedEof) {
                record(format!("phase=app_query step=header_eof frame={index} bytes={received}"));
                *first_header_eof = index == 1 && received == 0;
            }
            return Err(io_failure(error));
        }
        let length = u32::from_be_bytes(header);
        total += length as u64;
        if length == 0 || total > u64::from(MAX_REPLY) {
            return Err(failure("lookup", "code=query_invalid_size"));
        }
        record(format!("phase=app_query step=read_body frame={index} bytes={length}"));
        let bytes = client.idevice.read_raw(length as usize).await.map_err(io_failure)?;
        let mut reply: plist::Dictionary = plist::from_bytes(&bytes)
            .map_err(|_| failure("lookup", "code=query_invalid_plist"))?;
        if let Some(error) = reply.get("Error") {
            return Err(failure("lookup", format!("code={}", device_code(error))));
        }
        let status = match reply.get("Status") {
            None => "absent",
            Some(plist::Value::String(s)) if s == "Complete" => "complete",
            Some(plist::Value::String(_)) => "progress",
            Some(_) => return Err(failure("lookup", "code=query_invalid_status")),
        };
        let received_result = match reply.remove("LookupResult") {
            None => false,
            Some(plist::Value::Dictionary(entries)) => {
                result.get_or_insert_with(plist::Dictionary::new).extend(entries);
                true
            }
            Some(_) => return Err(failure("lookup", "code=query_invalid_result")),
        };
        record(format!("phase=app_query step=response frame={index} status={status} result_dictionary={received_result}"));
        // Keep compatibility with existing single-response services without a
        // Status key. A complete but unreadable inventory is always an error.
        if status == "complete" || (status == "absent" && received_result) {
            return result.ok_or_else(|| failure("lookup", "code=query_missing_result"));
        }
    }
    Err(failure("lookup", "code=query_frame_limit"))
}

async fn attempt(client: &mut InstallationProxyClient, message: &plist::Value,
    record: &mut impl FnMut(String)) -> Attempt
{
    // The caller's existing 30-second lookup/list timeout bounds the entire
    // exchange, including startup, reading progress frames and the final result.
    let mut first_header_eof = false;
    let result = run_inner(client, message, record, &mut first_header_eof).await;
    if let Err(error) = &result {
        record(format!("phase=app_query result=failed {}", error.message));
    }
    Attempt { result, first_header_eof }
}

#[cfg(test)]
async fn run(client: &mut InstallationProxyClient, message: &plist::Value,
    mut record: impl FnMut(String)) -> Result<plist::Dictionary, Failure>
{
    attempt(client, message, &mut record).await.result
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tls_tests;
