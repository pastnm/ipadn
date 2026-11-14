import XCTest
@testable import iPadn

final class NativeInstallerTests: XCTestCase {
    private func plist(_ value: [String: Any]) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)
    }

    private func remoteRecord() -> [String: Any] {
        ["public_key": Data(repeating: 7, count: 32), "private_key": Data(repeating: 8, count: 32), "identifier": "host"]
    }

    /// Deliberately not real credentials: only the Swift structural check is tested.
    /// Rust's offline tests cover parsing/rejecting cryptographic material.
    private func legacyRecord() -> [String: Any] {
        ["DeviceCertificate": Data([1]), "HostCertificate": Data([2]), "HostPrivateKey": Data([3]),
         "RootCertificate": Data([4]), "RootPrivateKey": Data([5]),
         "HostID": "test-host", "SystemBUID": "test-system", "WiFiMACAddress": "00:11:22:33:44:55"]
    }

    func testPairingFileValidationAcceptsBothFormats() throws {
        XCTAssertEqual(try NativeInstaller.pairingTransport(in: plist(remoteRecord())), .remotePairing)
        XCTAssertEqual(try NativeInstaller.pairingTransport(in: plist(legacyRecord())), .legacyLockdown)
        var remote = remoteRecord()
        remote["alt_irk"] = Data(count: 16)
        XCTAssertNoThrow(try NativeInstaller.validatePairingFile(plist(remote)))
        var legacy = legacyRecord()
        legacy["UDID"] = "test-device"
        legacy["WiFiMACAddress"] = "" // Pinned idevice accepts an empty value.
        legacy["EscrowBag"] = Data([9])
        XCTAssertNoThrow(try NativeInstaller.validatePairingFile(plist(legacy)))
        XCTAssertThrowsError(try NativeInstaller.validatePairingFile(Data("not a plist".utf8)))
        XCTAssertThrowsError(try NativeInstaller.validatePairingFile(Data(count: 64 * 1024 + 1)))
    }

    func testPairingFileRejectsIncompleteAndMixedRecords() throws {
        for key in ["public_key", "private_key", "identifier"] {
            var record = remoteRecord(); record.removeValue(forKey: key)
            XCTAssertThrowsError(try NativeInstaller.validatePairingFile(plist(record)), key)
        }
        var remote = remoteRecord(); remote["public_key"] = Data(count: 31)
        XCTAssertThrowsError(try NativeInstaller.validatePairingFile(plist(remote)))
        remote = remoteRecord(); remote["identifier"] = " \n"
        XCTAssertThrowsError(try NativeInstaller.validatePairingFile(plist(remote)))
        for key in ["DeviceCertificate", "HostCertificate", "HostPrivateKey", "RootCertificate", "RootPrivateKey", "HostID", "SystemBUID", "WiFiMACAddress"] {
            var record = legacyRecord(); record.removeValue(forKey: key)
            XCTAssertThrowsError(try NativeInstaller.validatePairingFile(plist(record)), key)
        }
        var legacy = legacyRecord(); legacy["HostPrivateKey"] = Data()
        XCTAssertThrowsError(try NativeInstaller.validatePairingFile(plist(legacy)))
        legacy = legacyRecord(); legacy["EscrowBag"] = "not data"
        XCTAssertThrowsError(try NativeInstaller.validatePairingFile(plist(legacy)))
        legacy = legacyRecord(); legacy["UDID"] = " \n"
        XCTAssertThrowsError(try NativeInstaller.validatePairingFile(plist(legacy)))
        var mixed = legacyRecord(); mixed["public_key"] = Data(count: 32)
        XCTAssertThrowsError(try NativeInstaller.validatePairingFile(plist(mixed)))
    }

    func testTransportRoutingKeepsIOS16OnLockdownAndModernRemoteIntact() throws {
        let legacy = try plist(legacyRecord()), remote = try plist(remoteRecord())
        XCTAssertEqual(try NativeInstaller.transportForRequest(legacy, supportsRemote: false), .legacyLockdown)
        XCTAssertEqual(try NativeInstaller.transportForRequest(legacy, supportsRemote: true), .legacyLockdown)
        XCTAssertEqual(try NativeInstaller.transportForRequest(remote, supportsRemote: true), .remotePairing)
        XCTAssertThrowsError(try NativeInstaller.transportForRequest(remote, supportsRemote: false)) { error in
            XCTAssertTrue(error.localizedDescription.contains("lockdown"))
        }
        XCTAssertEqual(NativeInstaller.lockdownPort, 62078)
        XCTAssertEqual(NativeInstaller.PairingTransport.legacyLockdown.rawValue, "legacy_lockdown")
        XCTAssertEqual(NativeInstaller.PairingTransport.remotePairing.rawValue, "remote_pairing")
    }

    func testLookupReplyDistinguishesStoreManifestAndMissingApps() throws {
        let store = try NativeInstaller.lookupResult(from: Data(#"{"ok":true,"app":{"installed":true,"version":"26.1.4","build":"59151816","signer":"Apple iPhone OS Application Signing","placeholder":false,"store_item_id":"477537958","store_version_id":"894270367","has_purchase_record":true,"manifest_install":false}}"#.utf8))
        XCTAssertTrue(store.recognisedByAppStore)
        XCTAssertEqual(store.version, "26.1.4")
        XCTAssertEqual(store.storeItemID, "477537958")

        let manifest = try NativeInstaller.lookupResult(from: Data(#"{"ok":true,"app":{"installed":true,"version":"3.20.1","store_item_id":null,"store_version_id":null,"has_purchase_record":false,"manifest_install":true}}"#.utf8))
        XCTAssertTrue(manifest.installed)
        XCTAssertFalse(manifest.recognisedByAppStore)

        let missing = try NativeInstaller.lookupResult(from: Data(#"{"ok":true,"app":{"installed":false}}"#.utf8))
        XCTAssertFalse(missing.installed)
        XCTAssertFalse(missing.recognisedByAppStore)

        // A reply without an app must not read as "not installed".
        XCTAssertThrowsError(try NativeInstaller.lookupResult(from: Data(#"{"ok":true}"#.utf8)))
        XCTAssertThrowsError(try NativeInstaller.lookupResult(from: Data("garbage".utf8)))
    }

    func testInstallReplyReportsUpgradeFailureStageAndCancellation() throws {
        let upgraded = try NativeInstaller.installResult(from: Data(#"{"ok":true,"upgraded":true,"before":{"installed":true},"after":{"installed":true,"store_item_id":"1","has_purchase_record":true,"manifest_install":false}}"#.utf8))
        XCTAssertTrue(upgraded.upgraded)
        XCTAssertEqual(upgraded.after?.recognisedByAppStore, true)

        let fresh = try NativeInstaller.installResult(from: Data(#"{"ok":true,"upgraded":false,"before":{"installed":false},"after":{"installed":true,"placeholder":false}}"#.utf8))
        XCTAssertFalse(fresh.upgraded)
        XCTAssertEqual(fresh.after?.installed, true)
        // Never report success when the post-install lookup is absent or incomplete.
        XCTAssertThrowsError(try NativeInstaller.installResult(from: Data(#"{"ok":true,"after":{}}"#.utf8)))
        for after in ["null", #"{"installed":false}"#, #"{"installed":true,"placeholder":true}"#] {
            XCTAssertThrowsError(try NativeInstaller.installResult(from: Data("{\"ok\":true,\"after\":\(after)}".utf8))) { error in
                XCTAssertEqual((error as? NativeInstaller.Failure)?.stage, "verify")
            }
        }

        XCTAssertThrowsError(try NativeInstaller.installResult(from: Data(#"{"ok":false,"stage":"pairing","message":"PairVerifyFailed"}"#.utf8))) { error in
            XCTAssertEqual(error as? NativeInstaller.Failure, NativeInstaller.Failure(stage: "pairing", detail: "PairVerifyFailed"))
            XCTAssertTrue(error.localizedDescription.contains("配对文件"))
        }
        XCTAssertThrowsError(try NativeInstaller.installResult(from: Data(#"{"ok":false,"stage":"cancelled","message":"cancelled"}"#.utf8))) { error in
            XCTAssertTrue(error is CancellationError)
        }
    }

    func testPairingEventsAndReplyAreParsedStrictly() throws {
        let ready = NativeInstaller.readyEvent(from: Data(#"{"port":53211,"identifier":"ABC","txt":{"name":"iPadn","flags":"1"}}"#.utf8))
        XCTAssertEqual(ready, .ready(port: 53211, identifier: "ABC", txt: ["name": "iPadn", "flags": "1"]))
        XCTAssertNil(NativeInstaller.readyEvent(from: Data(#"{"port":0,"identifier":"ABC","txt":{}}"#.utf8)))
        XCTAssertNil(NativeInstaller.readyEvent(from: Data(#"{"port":53211,"identifier":"","txt":{}}"#.utf8)))

        let file = Data("pairing".utf8)
        let reply = Data(#"{"ok":true,"device_name":"iPhone","pairing_file":"\#(file.base64EncodedString())"}"#.utf8)
        XCTAssertEqual(try NativeInstaller.pairingFile(fromReply: reply), file)
        XCTAssertThrowsError(try NativeInstaller.pairingFile(fromReply: Data(#"{"ok":true}"#.utf8)))
        XCTAssertThrowsError(try NativeInstaller.pairingFile(fromReply: Data(#"{"ok":false,"stage":"cancelled","message":""}"#.utf8))) { error in
            XCTAssertTrue(error is CancellationError)
        }
        XCTAssertTrue(NativeInstaller.message(stage: "timeout", detail: "").contains("5 分钟"))
    }

    func testFailureMessagesNameWhatTheUserCanFix() {
        XCTAssertTrue(NativeInstaller.message(stage: "connect", detail: "timed out").contains("LocalDevVPN"))
        XCTAssertTrue(NativeInstaller.message(stage: "install", detail: "ApplicationVerificationFailed").contains("验证"))
        XCTAssertTrue(NativeInstaller.message(stage: "install", detail: "DowngradeError").contains("降级"))
        XCTAssertTrue(NativeInstaller.message(stage: "upload", detail: "NoSpace").contains("存储空间"))
        XCTAssertTrue(NativeInstaller.message(stage: "lockdown_connect", detail: "timed out").contains("62078"))
        XCTAssertTrue(NativeInstaller.message(stage: "lockdown_connect", detail: "tcp=permission_denied errno=1").contains("本地网络"))
        XCTAssertTrue(NativeInstaller.message(stage: "lockdown_connect", detail: "tcp=connection_refused errno=61").contains("拒绝连接"))
        XCTAssertTrue(NativeInstaller.message(stage: "lockdown_connect", detail: "tcp=host_unreachable errno=65").contains("路由"))
        XCTAssertTrue(NativeInstaller.message(stage: "lockdown_route", detail: "no matching interface").contains("IPv4 VPN"))
        XCTAssertTrue(NativeInstaller.message(stage: "lockdown_session", detail: "rejected").contains("信任"))
        XCTAssertTrue(NativeInstaller.message(stage: "service_connect", detail: "timed out").contains("动态服务端口"))
        XCTAssertTrue(NativeInstaller.message(stage: "service_tls", detail: "failed").contains("TLS"))
        XCTAssertTrue(NativeInstaller.message(stage: "verify", detail: "missing app").contains("不要直接重复安装"))
        XCTAssertTrue(NativeInstaller.message(stage: "install", detail: "timed out").contains("可能仍在安装"))
        XCTAssertTrue(NativeInstaller.message(stage: "device_identity", detail: "mismatch").contains("停止安装"))
        // Unknown stages still surface the detail instead of hiding it.
        XCTAssertTrue(NativeInstaller.message(stage: "mystery", detail: "E42").contains("E42"))
    }

    func testNativeInstallationIsOptInAndKeepsTheOtherMethodChoice() throws {
        // Settings saved by earlier versions have no such key.
        var settings = try JSONDecoder().decode(ToolSettings.self, from: Data(#"{"automaticInstallation":false,"localInstallation":true}"#.utf8))
        XCTAssertFalse(settings.nativeInstallation)
        XCTAssertEqual(settings.installationMethodTitle, "本机证书")

        settings.nativeInstallation = true
        let restored = try JSONDecoder().decode(ToolSettings.self, from: JSONEncoder().encode(settings))
        XCTAssertTrue(restored.nativeInstallation)
        XCTAssertFalse(restored.automaticInstallation)
        XCTAssertTrue(restored.localInstallation)
        // Without the library (simulator, builds without it) the choice
        // falls back to the method chosen before.
        XCTAssertEqual(restored.usesNativeInstallation, NativeInstaller.isAvailable)
        XCTAssertEqual(restored.installationMethodTitle, NativeInstaller.isAvailable ? "原生安装" : "本机证书")
    }

    func testQueryFailureCategoriesNeverExposePeerText() {
        XCTAssertEqual(NativeInstaller.queryFailureCode("code=query_socket tcp=connection_reset errno=54"), "query_socket")
        XCTAssertTrue(NativeInstaller.message(stage: "lookup", detail: "code=query_device_locked").contains("解锁"))
        XCTAssertTrue(NativeInstaller.message(stage: "lookup", detail: "code=query_missing_result").contains("未返回有效"))
        XCTAssertTrue(NativeInstaller.message(stage: "list", detail: "code=query_socket").contains("query_socket"))
        XCTAssertTrue(NativeInstaller.message(stage: "lookup", detail: "code=query_socket io=unexpected_eof errno=0 tls=none").contains("连接提前结束"))
        for text in ["code=SENSITIVE", "code=query_socket\nSENSITIVE", "ErrorDescription=SENSITIVE"] {
            XCTAssertNil(NativeInstaller.queryFailureCode(text))
            XCTAssertFalse(NativeInstaller.message(stage: "lookup", detail: text).contains("SENSITIVE"))
        }
    }
}
