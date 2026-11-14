//! Fixed transport/TLS error categories. Never format an arbitrary error body.
use std::error::Error;
use std::io;

fn kind(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::UnexpectedEof => "unexpected_eof",
        io::ErrorKind::InvalidData => "invalid_data",
        io::ErrorKind::BrokenPipe => "broken_pipe",
        io::ErrorKind::WriteZero => "write_zero",
        io::ErrorKind::ConnectionAborted => "connection_aborted",
        io::ErrorKind::ConnectionReset => "connection_reset",
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::NotConnected => "not_connected",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        io::ErrorKind::NetworkDown => "network_down",
        io::ErrorKind::Other => "other",
        _ => "unclassified",
    }
}

fn tls(error: &rustls::Error) -> String {
    match error {
        // Numeric IANA alert code cannot include a remote error description.
        rustls::Error::AlertReceived(alert) => format!("alert_{}", u8::from(*alert)),
        rustls::Error::DecryptError => "decrypt_error".into(),
        rustls::Error::EncryptError => "encrypt_error".into(),
        rustls::Error::InvalidCertificate(_) => "invalid_certificate".into(),
        rustls::Error::InvalidCertRevocationList(_) => "invalid_revocation_list".into(),
        rustls::Error::NoCertificatesPresented => "no_certificates".into(),
        rustls::Error::PeerIncompatible(_) => "peer_incompatible".into(),
        rustls::Error::PeerMisbehaved(_) => "peer_misbehaved".into(),
        rustls::Error::InappropriateMessage { .. } => "unexpected_message".into(),
        rustls::Error::InappropriateHandshakeMessage { .. } => "unexpected_handshake".into(),
        rustls::Error::InvalidMessage(_) => "invalid_message".into(),
        rustls::Error::General(_) => "general_error".into(),
        _ => "unclassified".into(),
    }
}

pub(crate) fn io_detail(error: &io::Error) -> String {
    let mut cause: Option<&(dyn Error + 'static)> = error.get_ref().map(|e| e as _);
    let mut tls_code = "none".to_owned();
    for _ in 0..6 {
        let Some(current) = cause else { break };
        if let Some(error) = current.downcast_ref::<rustls::Error>() {
            tls_code = tls(error);
            break;
        }
        // io::Error's source may skip its directly wrapped error.
        cause = current.downcast_ref::<io::Error>()
            .and_then(|e| e.get_ref().map(|inner| inner as &(dyn Error + 'static)))
            .or_else(|| current.source());
    }
    format!("io={} errno={} tls={tls_code}", kind(error), error.raw_os_error().unwrap_or(0))
}

pub(crate) fn idevice_detail(error: &idevice::IdeviceError) -> String {
    match error {
        idevice::IdeviceError::Socket(error) => io_detail(error),
        idevice::IdeviceError::Rustls(error) => format!("io=none errno=0 tls={}", tls(error)),
        _ => "io=none errno=0 tls=none".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eof_and_crypto_errors_are_distinct_without_raw_descriptions() {
        assert_eq!(io_detail(&io::Error::new(io::ErrorKind::UnexpectedEof,"SENSITIVE")),
            "io=unexpected_eof errno=0 tls=none");
        let alert = rustls::Error::AlertReceived(rustls::AlertDescription::BadCertificate);
        assert_eq!(io_detail(&io::Error::new(io::ErrorKind::InvalidData,alert)),
            "io=invalid_data errno=0 tls=alert_42");
        let error = io::Error::new(io::ErrorKind::InvalidData,rustls::Error::General("SENSITIVE".into()));
        let nested=io::Error::other(error);
        let text=io_detail(&nested);
        assert!(text.contains("tls=general_error"));
        assert!(!text.contains("SENSITIVE"));
        assert_eq!(io_detail(&io::Error::from_raw_os_error(54)),"io=connection_reset errno=54 tls=none");
    }
}
