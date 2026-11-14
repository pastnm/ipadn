//! Test-only peer framing using idevice's public raw I/O API.
use idevice::{Idevice, IdeviceError};

macro_rules! message {
    ({$($key:literal : $value:expr),* $(,)?}) => {{
        let mut d = plist::Dictionary::new();
        $(d.insert($key.into(), plist::Value::from($value));)*
        plist::Value::Dictionary(d)
    }};
}
pub(crate) use message;

pub(crate) trait Wire {
    async fn send_message(&mut self, message: plist::Value) -> Result<(), IdeviceError>;
    async fn read_message(&mut self) -> Result<plist::Dictionary, IdeviceError>;
}
impl Wire for Idevice {
    async fn send_message(&mut self, message: plist::Value) -> Result<(), IdeviceError> {
        let mut body = Vec::new(); plist::to_writer_xml(&mut body, &message).unwrap();
        self.send_raw(&(body.len() as u32).to_be_bytes()).await?;
        self.send_raw(&body).await
    }
    async fn read_message(&mut self) -> Result<plist::Dictionary, IdeviceError> {
        let header = self.read_raw(4).await?;
        let length = u32::from_be_bytes(header.try_into().unwrap());
        assert!(length <= 1024 * 1024);
        let body = self.read_raw(length as usize).await?;
        Ok(plist::from_bytes(&body).unwrap())
    }
}
