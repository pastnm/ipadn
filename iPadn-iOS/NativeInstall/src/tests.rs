//! Pure offline tests: no device, VPN, pairing databases or installation.
use super::*;
use base64::Engine;

fn request_value() -> Json {
    json!({
        "pairing_file": "imported-test-record.plist",
        "host": "10.7.0.1",
        "port": 62078,
        "bundle_id": "example.test"
    })
}

#[test]
fn missing_transport_keeps_remote_pairing_compatibility() {
    let request: Request = serde_json::from_value(request_value()).ok().expect("old request");
    assert!(request.transport == Transport::RemotePairing);
}

#[test]
fn explicit_transports_are_distinct_and_unknown_never_falls_back() {
    for (text, transport) in [
        ("legacy_lockdown", Transport::LegacyLockdown),
        ("remote_pairing", Transport::RemotePairing),
    ] {
        let mut value = request_value();
        value["transport"] = json!(text);
        let request: Request = serde_json::from_value(value).ok().expect("valid request");
        assert!(request.transport == transport);
    }
    for value in [json!("legacy"), json!(""), Json::Null, json!(123), json!({})] {
        let mut request = request_value();
        request["transport"] = value;
        assert!(serde_json::from_value::<Request>(request).is_err());
    }
}

#[test]
fn ffi_invalid_transport_does_not_echo_request_secrets() {
    let mut value = request_value();
    value["transport"] = json!("SENSITIVE_HOST_PRIVATE_KEY");
    let input = CString::new(value.to_string()).unwrap();
    // Deserialization fails before the runtime, file access or connect.
    let reply = unsafe { iPadnNativeLookup(input.as_ptr()) };
    assert!(!reply.is_null());
    let text = unsafe { CStr::from_ptr(reply) }.to_str().unwrap().to_owned();
    unsafe { iPadnNativeFree(reply) };
    let reply: Json = serde_json::from_str(&text).unwrap();
    assert_eq!(reply["ok"], json!(false));
    assert_eq!(reply["stage"], json!("request"));
    assert!(!text.contains("SENSITIVE_HOST_PRIVATE_KEY"));
}

fn metadata_bytes() -> Vec<u8> {
    let mut d = plist::Dictionary::new();
    d.insert("itemId".into(), 123u64.into());
    d.insert("softwareVersionExternalIdentifier".into(), "456".into());
    d.insert("com.apple.iTunesStore.downloadInfo".into(), plist::Value::Dictionary(plist::Dictionary::new()));
    let mut bytes = Vec::new();
    plist::Value::Dictionary(d).to_writer_binary(&mut bytes).unwrap();
    bytes
}

#[test]
fn metadata_is_validated_offline_before_upload() {
    assert!(decode_metadata(None).ok().unwrap().is_none());
    for text in ["not base64 SENSITIVE", "U0VOU0lUSVZF"] {
        let e = decode_metadata(Some(text)).err().expect("reject malformed metadata");
        assert_eq!(e.stage, "request");
        assert!(!e.message.contains("SENSITIVE"));
    }
    let bytes = metadata_bytes();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    assert_eq!(decode_metadata(Some(&encoded)).ok().unwrap(), Some(bytes));
}

fn installed() -> Json {
    json!({
        "installed": true,
        "bundle_id": "example.test",
        "placeholder": false,
        "store_item_id": "123",
        "store_version_id": "456",
        "has_purchase_record": true
    })
}

#[test]
fn post_install_requires_app_and_requested_purchase_metadata() {
    let good = installed();
    let expected = metadata_bytes();
    assert!(verify_installation("example.test", &json!({}), &good, Some(&expected)).is_ok());
    for (field, bad) in [
        ("installed", json!(false)),
        ("bundle_id", json!("other.app")),
        ("placeholder", json!(true)),
        ("store_item_id", json!("999")),
        ("store_version_id", Json::Null),
        ("has_purchase_record", json!(false)),
    ] {
        let mut after = good.clone();
        after[field] = bad;
        let error = verify_installation("example.test", &json!({}), &after, Some(&expected))
            .err().expect("verification must fail");
        assert_eq!(error.stage, "verify");
    }
}

#[test]
fn upgrade_cannot_silently_lose_existing_purchase_record() {
    let before = installed();
    let mut after = before.clone();
    after["store_version_id"] = json!("789"); // upgrading may change this ID
    assert!(verify_installation("example.test", &before, &after, None).is_ok());
    after["has_purchase_record"] = json!(false);
    assert!(verify_installation("example.test", &before, &after, None).is_err());
}
