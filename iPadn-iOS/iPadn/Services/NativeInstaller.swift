import Foundation
import Network
import UIKit
import ZIPFoundation

// Swift side of NativeInstall (Rust + idevice). It reaches this device's own
// installation service, the one desktop tools use over USB, through a loopback
// VPN and a remote pairing file. Unlike an install link, the system keeps the
// package's App Store purchase record and replaces an App Store copy in place.
// Symbols are resolved at runtime: simulator builds and builds made without
// scripts/build_native_install.sh report the feature unavailable.
enum NativeInstaller {
    /// What the system has installed for one bundle ID.
    struct InstalledApp: Decodable, Equatable {
        var installed = false
        var bundleID: String?
        var name: String?
        var version: String?
        var build: String?
        var signer: String?
        var placeholder: Bool?
        var storeItemID: String?
        var storeVersionID: String?
        var hasPurchaseRecord: Bool?
        /// Installed from an install link, which the App Store does not recognise.
        var manifestInstall: Bool?
        private enum CodingKeys: String, CodingKey {
            case installed, version, build, signer, placeholder, name
            case bundleID = "bundle_id"
            case storeItemID = "store_item_id", storeVersionID = "store_version_id"
            case hasPurchaseRecord = "has_purchase_record", manifestInstall = "manifest_install"
        }
        /// The App Store can show "Open" and offer updates for this copy.
        var recognisedByAppStore: Bool { installed && storeItemID != nil && hasPurchaseRecord == true && manifestInstall != true }
        /// Installed with "Block App Store Updates".
        var updatesBlocked: Bool { storeVersionID == String(NativeInstaller.blockedVersionID) }
    }
    struct Outcome: Equatable {
        let upgraded: Bool
        let after: InstalledApp?
    }
    enum Phase: Equatable {
        case connecting
        case uploading(Double)
        case installing(Double)
    }
    /// A failure with the step it happened in, so the message can say what to fix.
    struct Failure: LocalizedError, Equatable {
        let stage: String
        let detail: String
        var errorDescription: String? { NativeInstaller.message(stage: stage, detail: detail) }
    }

    /// This device, as seen through the loopback VPN.
    static let deviceAddress = "10.7.0.1"
    /// Where the system listens when discovery finds nothing.
    static let fallbackPort: UInt16 = 49152

    private typealias ProgressFunction = @convention(c) (UnsafeMutableRawPointer?, Int32, UInt64, UInt64) -> Void
    private typealias InstallFunction = @convention(c) (UnsafePointer<CChar>, ProgressFunction?, UnsafeMutableRawPointer?) -> UnsafeMutablePointer<CChar>?
    private typealias LookupFunction = @convention(c) (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
    private typealias CancelFunction = @convention(c) () -> Void
    private typealias FreeFunction = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void
    private typealias EventFunction = @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafePointer<CChar>?) -> Void
    private typealias PairFunction = @convention(c) (UnsafePointer<CChar>, EventFunction?, UnsafeMutableRawPointer?) -> UnsafeMutablePointer<CChar>?

    private static func symbol<T>(_ name: String, as type: T.Type) -> T? {
        guard let handle = dlopen(nil, RTLD_NOW), let pointer = dlsym(handle, name) else { return nil }
        return unsafeBitCast(pointer, to: type)
    }
    private static let installFunction = symbol("iPadnNativeInstall", as: InstallFunction.self)
    private static let lookupFunction = symbol("iPadnNativeLookup", as: LookupFunction.self)
    private static let cancelFunction = symbol("iPadnNativeCancel", as: CancelFunction.self)
    private static let freeFunction = symbol("iPadnNativeFree", as: FreeFunction.self)
    private static let pairFunction = symbol("iPadnNativePair", as: PairFunction.self)
    private static let listFunction = symbol("iPadnNativeList", as: LookupFunction.self)
    private static let pairCancelFunction = symbol("iPadnNativePairCancel", as: CancelFunction.self)

    /// This build can list the apps installed on the device.
    static var listingIsAvailable: Bool { isAvailable && listFunction != nil }

    /// This build can create a pairing file on the device.
    static var pairingIsAvailable: Bool { isAvailable && pairFunction != nil && pairCancelFunction != nil }

    static var isAvailable: Bool {
        installFunction != nil && lookupFunction != nil && cancelFunction != nil && freeFunction != nil
    }

    // MARK: Pairing file

    private static var directory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(LocalResources.isPreview ? "NativeInstallPreview" : "NativeInstall", isDirectory: true)
    }
    static var pairingFileURL: URL { directory.appendingPathComponent("pairing.plist") }
    static var hasPairingFile: Bool { FileManager.default.fileExists(atPath: pairingFileURL.path) }

    /// RPPairing uses the modern remote service; certificate records use lockdown.
    enum PairingTransport: String {
        case remotePairing = "remote_pairing"
        case legacyLockdown = "legacy_lockdown"
    }
    static var supportsRemotePairing: Bool {
        ProcessInfo.processInfo.isOperatingSystemAtLeast(
            OperatingSystemVersion(majorVersion: 17, minorVersion: 4, patchVersion: 0))
    }
    static let lockdownPort: UInt16 = 62078

    /// Structural validation only. Rust validates the certificate/key material
    /// before starting TLS. Never include credential contents in an error/log.
    static func pairingTransport(in data: Data) throws -> PairingTransport {
        guard !data.isEmpty, data.count <= 64 * 1024,
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            throw ToolError.message(AppText.text("这不是有效的配对文件。"))
        }
        let legacyKeys = ["DeviceCertificate", "HostCertificate", "HostPrivateKey", "RootCertificate", "RootPrivateKey", "HostID", "SystemBUID", "WiFiMACAddress"]
        let remoteKeys = ["public_key", "private_key", "identifier"]
        let hasLegacy = legacyKeys.contains { plist[$0] != nil }
        let hasRemote = remoteKeys.contains { plist[$0] != nil }
        guard !(hasLegacy && hasRemote) else {
            throw ToolError.message(AppText.text("配对文件混合了两种格式，请重新导出。"))
        }
        if hasLegacy {
            let certificates = ["DeviceCertificate", "HostCertificate", "HostPrivateKey", "RootCertificate", "RootPrivateKey"]
            guard certificates.allSatisfy({ (plist[$0] as? Data)?.isEmpty == false }),
                  let hostID = plist["HostID"] as? String, !hostID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  let systemBUID = plist["SystemBUID"] as? String, !systemBUID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  plist["WiFiMACAddress"] is String,
                  plist["EscrowBag"] == nil || plist["EscrowBag"] is Data,
                  plist["UDID"] == nil || ((plist["UDID"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false) else {
                throw ToolError.message(AppText.text("传统 lockdown 配对文件不完整，请从已信任这台设备的电脑重新导出。"))
            }
            return .legacyLockdown
        }
        guard (plist["public_key"] as? Data)?.count == 32, (plist["private_key"] as? Data)?.count == 32,
              let identifier = plist["identifier"] as? String, !identifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ToolError.message(AppText.text("这不是有效的远程配对文件。请在电脑上用 idevice_pair 生成「远程配对（RPPairing）」文件。"))
        }
        return .remotePairing
    }

    static func validatePairingFile(_ data: Data) throws {
        _ = try pairingTransport(in: data)
    }

    /// Kept independent of the running OS so both routing branches can be tested.
    static func transportForRequest(_ data: Data, supportsRemote: Bool) throws -> PairingTransport {
        let transport = try pairingTransport(in: data)
        if transport == .remotePairing && !supportsRemote {
            throw ToolError.message(AppText.text("iOS 16 至 17.3 需要传统 lockdown 配对文件，不支持远程配对（RPPairing）。请从已信任这台设备的电脑导出传统配对文件后导入。"))
        }
        return transport
    }

    static func importPairingFile(_ data: Data) throws {
        try validatePairingFile(data)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        // The file is a credential for this device: keep it out of backups
        // and unreadable while the device is locked.
        try data.write(to: pairingFileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var url = pairingFileURL
        try? url.setResourceValues(values)
    }

    /// Imports a pairing file placed in iPadn's folder in the Files app
    /// (copied there from a computer or another app). The first valid one
    /// wins and is removed from that folder once imported.
    /// Returns whether one was found.
    @discardableResult
    static func importPairingFileFromDocuments() throws -> Bool {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let names = (try? FileManager.default.contentsOfDirectory(atPath: documents.path)) ?? []
        let candidates = names.filter {
            let ext = ($0 as NSString).pathExtension.lowercased()
            return ["plist", "rppairing", "mobiledevicepairing", "pairing"].contains(ext)
        }.sorted()
        var rejected: Error?
        for name in candidates {
            let url = documents.appendingPathComponent(name)
            guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 64 * 1024,
                  let data = try? Data(contentsOf: url) else { continue }
            do {
                try importPairingFile(data)
                try? FileManager.default.removeItem(at: url)
                return true
            } catch { rejected = rejected ?? error }
        }
        if let rejected { throw rejected }
        return false
    }

    static func removePairingFile() throws {
        guard hasPairingFile else { return }
        try FileManager.default.removeItem(at: pairingFileURL)
    }

    // MARK: Requests

    /// One operation at a time: the library keeps one cancellation flag.
    private static let gate = NSLock()
    private static var running = false
    private static func begin() throws {
        gate.lock(); defer { gate.unlock() }
        guard !running else { throw ToolError.message(AppText.text("另一个安装正在进行，请稍候。")) }
        running = true
    }
    private static func end() { gate.lock(); running = false; gate.unlock() }

    /// The App Store compares this version ID in the installed purchase record
    /// with the newest release; one above every real ID reads as up to date.
    static let blockedVersionID = 2_000_000_000

    /// The package's purchase record with the version ID raised, for the
    /// system to keep instead of the package's own (issue #46). nil when the
    /// package has none.
    static func blockedMetadata(of package: URL) throws -> Data? {
        let archive = try Archive(url: package, accessMode: .read)
        guard let entry = archive["iTunesMetadata.plist"], entry.uncompressedSize < 4 * 1024 * 1024 else { return nil }
        var data = Data()
        _ = try archive.extract(entry) { data.append($0) }
        guard var record = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return nil }
        record["softwareVersionExternalIdentifier"] = blockedVersionID
        return try PropertyListSerialization.data(fromPropertyList: record, format: .binary, options: 0)
    }

    private static func connection() async throws -> (transport: PairingTransport, port: UInt16) {
        guard isAvailable else { throw ToolError.message(AppText.text("当前版本不包含原生安装组件。")) }
        guard hasPairingFile else { throw ToolError.message(AppText.text("请先在安装方式中导入配对文件。")) }
        guard let size = try pairingFileURL.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 64 * 1024 else {
            throw ToolError.message(AppText.text("这不是有效的配对文件。"))
        }
        let transport = try transportForRequest(Data(contentsOf: pairingFileURL), supportsRemote: supportsRemotePairing)
        // lockdown has its own fixed port; never run RPPairing discovery for it.
        let port: UInt16
        if transport == .legacyLockdown { port = lockdownPort }
        else { port = await RemotePairingPort.resolve() }
        return (transport, port)
    }

    private static func request(bundleID: String, package: URL?, port: UInt16, transport: PairingTransport, metadata: Data? = nil) throws -> String {
        guard isAvailable else { throw ToolError.message(AppText.text("当前版本不包含原生安装组件。")) }
        guard hasPairingFile else { throw ToolError.message(AppText.text("请先在安装方式中导入配对文件。")) }
        guard !bundleID.isEmpty else { throw ToolError.message(AppText.text("安装包信息不完整，无法安装。")) }
        var body: [String: Any] = ["pairing_file": pairingFileURL.path, "host": deviceAddress,
                                   "port": Int(port), "bundle_id": bundleID, "hostname": "iPadn",
                                   "transport": transport.rawValue]
        if let package { body["ipa"] = package.path }
        if let metadata { body["metadata"] = metadata.base64EncodedString() }
        return String(decoding: try JSONSerialization.data(withJSONObject: body), as: UTF8.self)
    }

    private struct Reply: Decodable {
        let ok: Bool
        let stage: String?
        let message: String?
        let upgraded: Bool?
        let app: InstalledApp?
        let apps: [InstalledApp]?
        let after: InstalledApp?
        let connection_diagnostics: [String]?
    }
    private static func decode(_ pointer: UnsafeMutablePointer<CChar>?) throws -> Reply {
        guard let pointer else { throw Failure(stage: "reply", detail: "no reply") }
        defer { freeFunction?(pointer) }
        return try parse(Data(String(cString: pointer).utf8))
    }
    private static func parse(_ data: Data) throws -> Reply {
        guard let reply = try? JSONDecoder().decode(Reply.self, from: data) else {
            throw Failure(stage: "reply", detail: "unreadable reply")
        }
        // Fixed protocol categories and interface metadata only. No peer values.
        // Never log the request, pairing record or arbitrary upstream errors.
        for line in reply.connection_diagnostics ?? [] {
            let kind = line.hasPrefix("phase=") ? "protocol" : "transport"
            InstallLog.shared.add("native \(kind): \(String(line.prefix(300)))")
        }
        if !reply.ok {
            let stage = reply.stage ?? "unknown"
            if stage.count <= 40, stage.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }) {
                InstallLog.shared.add("native request failed at \(stage)")
            }
            if reply.stage == "cancelled" { throw CancellationError() }
            throw Failure(stage: reply.stage ?? "unknown", detail: reply.message ?? "")
        }
        return reply
    }
    /// The parsed result of a lookup reply. Internal so tests can cover it.
    static func lookupResult(from data: Data) throws -> InstalledApp {
        guard let app = try parse(data).app else { throw Failure(stage: "reply", detail: "missing app") }
        return app
    }
    private static func outcome(from reply: Reply) throws -> Outcome {
        guard let after = reply.after, after.installed, after.placeholder != true else {
            throw Failure(stage: "verify", detail: "installed app was not verified")
        }
        return Outcome(upgraded: reply.upgraded ?? false, after: after)
    }
    static func installResult(from data: Data) throws -> Outcome {
        try outcome(from: parse(data))
    }

    /// Reports what the system has installed for `bundleID`. Also the
    /// connection check: it goes through the VPN, the pairing and the tunnel.
    static func lookup(bundleID: String) async throws -> InstalledApp {
        try begin(); defer { end() }
        let (transport, port) = try await connection()
        let body = try request(bundleID: bundleID, package: nil, port: port, transport: transport)
        InstallLog.shared.add("native lookup (port \(port))")
        return try await Task.detached(priority: .userInitiated) {
            guard let lookupFunction else { throw ToolError.message(AppText.text("当前版本不包含原生安装组件。")) }
            let reply = try decode(body.withCString { lookupFunction($0) })
            guard let app = reply.app else { throw Failure(stage: "reply", detail: "missing app") }
            return app
        }.value
    }

    /// Every app the user installed on this device. Reads only; nothing changes.
    static func installedApps() async throws -> [InstalledApp] {
        try begin(); defer { end() }
        let (transport, port) = try await connection()
        let body = try request(bundleID: "*", package: nil, port: port, transport: transport)
        InstallLog.shared.add("native list (port \(port))")
        return try await Task.detached(priority: .userInitiated) {
            guard let listFunction else { throw ToolError.message(AppText.text("当前版本不包含原生安装组件。")) }
            let reply = try decode(body.withCString { listFunction($0) })
            guard let apps = reply.apps else { throw Failure(stage: "reply", detail: "missing apps") }
            return apps
        }.value
    }
    /// The parsed result of a list reply. Internal so tests can cover it.
    static func listResult(from data: Data) throws -> [InstalledApp] {
        guard let apps = try parse(data).apps else { throw Failure(stage: "reply", detail: "missing apps") }
        return apps
    }

    private final class ProgressBox: @unchecked Sendable {
        let handler: @Sendable (Phase) -> Void
        init(_ handler: @escaping @Sendable (Phase) -> Void) { self.handler = handler }
    }

    /// Installs `package`, replacing an installed copy in place. The package
    /// stays on this device; it is handed to the system installer directly.
    static func install(package: URL, bundleID: String, blockUpdates: Bool = false,
                        progress: @escaping @Sendable (Phase) -> Void) async throws -> Outcome {
        try begin(); defer { end() }
        let (transport, port) = try await connection()
        var metadata: Data?
        if blockUpdates {
            guard let record = try blockedMetadata(of: package) else {
                throw ToolError.message(AppText.text("这个安装包没有购买记录，无法阻止 App Store 更新。"))
            }
            metadata = record
        }
        let body = try request(bundleID: bundleID, package: package, port: port, transport: transport, metadata: metadata)
        InstallLog.shared.add("native install started (port \(port))")
        // Sending the package takes a while; keep running if the user leaves.
        let background = await UIApplication.shared.beginBackgroundTask(withName: "iPadn native installation") { cancel() }
        defer { Task { @MainActor in UIApplication.shared.endBackgroundTask(background) } }
        do {
            let outcome = try await Task.detached(priority: .userInitiated) {
                guard let installFunction else { throw ToolError.message(AppText.text("当前版本不包含原生安装组件。")) }
                let box = Unmanaged.passRetained(ProgressBox(progress))
                defer { box.release() }
                let callback: ProgressFunction = { context, phase, done, total in
                    guard let context else { return }
                    let fraction = total > 0 ? min(1, Double(done) / Double(total)) : 0
                    let handler = Unmanaged<ProgressBox>.fromOpaque(context).takeUnretainedValue().handler
                    switch phase {
                    case 1: handler(.uploading(fraction))
                    case 2: handler(.installing(fraction))
                    default: handler(.connecting)
                    }
                }
                let reply = try decode(body.withCString { installFunction($0, callback, box.toOpaque()) })
                return try NativeInstaller.outcome(from: reply)
            }.value
            InstallLog.shared.add("native install finished (\(outcome.upgraded ? "upgrade" : "install"))")
            return outcome
        } catch {
            if let failure = error as? Failure { InstallLog.shared.add("native install failed at \(failure.stage): \(failure.detail.prefix(200))") }
            throw error
        }
    }

    /// Stops sending the package. An install the system already started continues.
    static func cancel() { cancelFunction?() }

    // MARK: On-device pairing

    enum PairingEvent: Equatable {
        /// Listening; advertise this port, service name and TXT record.
        case ready(port: Int, identifier: String, txt: [String: String])
        case connected
        case code(String)
    }
    private final class EventBox: @unchecked Sendable {
        let handler: @Sendable (PairingEvent) -> Void
        init(_ handler: @escaping @Sendable (PairingEvent) -> Void) { self.handler = handler }
    }
    /// Parses the ready event. Internal so tests can cover it.
    static func readyEvent(from data: Data) -> PairingEvent? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let port = object["port"] as? Int, (1...65535).contains(port),
              let identifier = object["identifier"] as? String, !identifier.isEmpty,
              let txt = object["txt"] as? [String: String] else { return nil }
        return .ready(port: port, identifier: identifier, txt: txt)
    }
    /// The pairing file in a successful pair reply. Internal so tests can cover it.
    static func pairingFile(fromReply data: Data) throws -> Data {
        _ = try parse(data)
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let encoded = object["pairing_file"] as? String, let file = Data(base64Encoded: encoded) else {
            throw Failure(stage: "reply", detail: "missing pairing file")
        }
        return file
    }

    /// Waits for the device to pair with iPadn and returns the new pairing
    /// file. Blocks until the user finishes in Settings, gives up or cancels.
    static func pair(name: String, events: @escaping @Sendable (PairingEvent) -> Void) async throws -> Data {
        guard pairingIsAvailable else { throw ToolError.message(AppText.text("当前版本不包含本机配对组件。")) }
        try begin(); defer { end() }
        let body = String(decoding: try JSONSerialization.data(withJSONObject: ["name": name]), as: UTF8.self)
        return try await Task.detached(priority: .userInitiated) {
            guard let pairFunction, let freeFunction else { throw ToolError.message(AppText.text("当前版本不包含本机配对组件。")) }
            let box = Unmanaged.passRetained(EventBox(events))
            defer { box.release() }
            let callback: EventFunction = { context, kind, payload in
                guard let context else { return }
                let text = payload.map { String(cString: $0) } ?? ""
                let handler = Unmanaged<EventBox>.fromOpaque(context).takeUnretainedValue().handler
                switch kind {
                case 0: if let event = NativeInstaller.readyEvent(from: Data(text.utf8)) { handler(event) }
                case 1: handler(.connected)
                case 2: handler(.code(text))
                default: break
                }
            }
            guard let reply = body.withCString({ pairFunction($0, callback, box.toOpaque()) }) else {
                throw Failure(stage: "reply", detail: "no reply")
            }
            defer { freeFunction(reply) }
            return try pairingFile(fromReply: Data(String(cString: reply).utf8))
        }.value
    }

    static func cancelPairing() { pairCancelFunction?() }

    // MARK: Messages

    static func queryFailureCode(_ detail: String) -> String? {
        guard let first = detail.split(separator: " ").first, first.hasPrefix("code=") else { return nil }
        let code = String(first.dropFirst(5))
        let allowed: Set<String> = ["query_socket", "query_tls", "query_timed_out", "query_transport_error",
            "query_encode_failed", "query_invalid_size", "query_invalid_header", "query_invalid_plist",
            "query_invalid_status", "query_invalid_result", "query_missing_result", "query_frame_limit",
            "query_device_locked", "query_device_lookup_failed", "query_invalid_options", "query_invalid_command",
            "query_access_denied", "query_session_rejected", "query_device_rejected"]
        return allowed.contains(code) ? code : nil
    }

    static func message(stage: String, detail: String) -> String {
        let lowered = detail.lowercased()
        switch stage {
        case "connect":
            return AppText.text("无法连接本机安装服务。请先在 LocalDevVPN 中点按连接，并保持 Wi-Fi 开启；如果正在使用其他代理或 VPN，需要先切换到 LocalDevVPN。")
        case "pairing_file":
            return AppText.text("无法读取或验证配对文件，请从已信任这台设备的电脑重新导出并导入。")
        case "lockdown_connect":
            if lowered.contains("permission_denied") {
                return AppText.text("系统拒绝了本机网络连接。请在系统提示时允许 iPadn 访问本地网络；如果已拒绝，请在「设置 › 隐私与安全性 › 本地网络」中开启。")
            }
            if lowered.contains("connection_refused") {
                return AppText.text("VPN 接口上的 lockdown 62078 端口拒绝连接。请保持 Wi-Fi 开启、解锁设备，并在 LocalDevVPN 中断开后重新连接；暂时不需要重新配对。")
            }
            if lowered.contains("network_unreachable") || lowered.contains("host_unreachable") || lowered.contains("network_down") || lowered.contains("interface_unavailable") {
                return AppText.text("本机 VPN 路由不可用或接口已断开。请在 LocalDevVPN 中重新连接，并确认设备地址仍为 10.7.0.1。")
            }
            if lowered.contains("timed_out") || lowered.contains("timed out") {
                return AppText.text("连接 VPN 接口上的 lockdown 62078 端口超时，尚未进入配对认证。请确认 LocalDevVPN 已连接并保持 Wi-Fi 开启；如仍失败，请从「账号 › 设置 › 维护」导出诊断信息。")
            }
            return AppText.text("无法连接本机 lockdown 服务。请连接可信的环回 VPN，并确认 10.7.0.1 的 62078 端口可达。")
        case "lockdown_route":
            return AppText.text("未找到受支持的活动 IPv4 回环 VPN 接口。请连接 LocalDevVPN，或启用回环插件后连接 Loon；如仍失败，请从「账号 › 设置 › 维护」复制诊断信息。")
        case "lockdown_session":
            return AppText.text("无法建立 lockdown 配对会话。请解锁设备，并确认配对文件来自这台设备、信任关系仍有效。")
        case "lockdown_service", "service_connect":
            return AppText.text("无法启动或连接系统安装服务。请解锁设备，并确认环回 VPN 同时允许动态服务端口，而不只是 62078。")
        case "device_identity":
            return AppText.text("VPN 目标与配对文件中的设备不一致，或无法核实设备身份。请停止安装并检查可信的本机路由与配对文件。")
        case "service_tls":
            return AppText.text("系统安装服务的 TLS 验证失败，请检查配对文件与可信的本机 VPN 路由。")
        case "heartbeat_setup":
            return AppText.text("无法建立设备保活连接。请保持设备解锁和 LocalDevVPN 连接后重试；如仍失败，请从「账号 › 设置 › 维护」复制诊断信息。")
        case "heartbeat_lost":
            return AppText.text("设备保活连接已中断。若刚才正在安装，系统可能仍会完成；请先检查本机应用和 App Store 状态，再检查连接，不要直接重复安装。")
        case "verify":
            return AppText.text("系统安装步骤已结束，但未能核实应用或购买记录。请先检查本机应用和 App Store 状态，不要直接重复安装。")
        case "pairing" where lowered.contains("pair-verify") || lowered.contains("auth") || lowered.contains("srp"):
            return AppText.text("配对没有完成。请确认输入的配对码正确，然后重试。")
        case "pairing":
            return AppText.text("系统没有接受这份配对文件。配对文件可能已失效（系统更新、还原或重新信任电脑之后），请在电脑上重新生成并导入。")
        case "tunnel":
            return AppText.text("已连接但无法建立安装通道。请确认设备已解锁，然后重试。")
        case "lookup", "list":
            let code = queryFailureCode(detail)
            let suffix = code.map { "（\($0)）" } ?? ""
            if code == "query_device_locked" {
                return AppText.text("安装服务要求解锁设备后再读取应用信息，请解锁后重试。") + suffix
            }
            if code == "query_socket" && lowered.contains("io=unexpected_eof") {
                return AppText.text("安装服务连接提前结束，尚未读完应用信息。请从「账号 › 设置 › 维护」复制诊断信息。") + suffix
            }
            if code == "query_missing_result" || code == "query_invalid_result" {
                return AppText.text("安装服务未返回有效的应用查询结果。请从「账号 › 设置 › 维护」复制诊断信息。") + suffix
            }
            return AppText.text("读取设备应用信息失败。请从「账号 › 设置 › 维护」复制诊断信息。") + suffix
        case "listen", "accept":
            return AppText.text("无法开始配对，请确认已允许 iPadn 访问本地网络，然后重试。")
        case "timeout":
            return AppText.text("等待配对超时。请重新开始，并在 5 分钟内于「设置」中完成配对。")
        case "package":
            return AppText.text("无法读取安装包文件，请重新下载。")
        case "upload":
            return lowered.contains("nospace") || lowered.contains("no space") ? AppText.text("设备存储空间不足，无法安装。") : AppText.text("安装包传输中断，请保持 LocalDevVPN 连接后重试。")
        case "install":
            if lowered.contains("timed out") {
                return AppText.text("等待系统安装结果超时，系统可能仍在安装。请先检查本机应用和 App Store 状态，不要直接重复安装。")
            }
            if lowered.contains("applicationverificationfailed") || lowered.contains("verification") {
                return AppText.text("系统无法验证这个安装包。请确认它是用当前登录设备 App Store 的账号获取的，或重新下载。")
            }
            if lowered.contains("downgrade") { return AppText.text("设备上已安装更新的版本，系统不允许降级覆盖。") }
            if lowered.contains("notenoughspace") || lowered.contains("no space") { return AppText.text("设备存储空间不足，无法安装。") }
            return detail.isEmpty ? AppText.text("系统安装失败：未知错误")
                : AppText.text("系统安装失败：\(String(detail.prefix(160)))")
        default:
            return detail.isEmpty ? AppText.text("原生安装失败（\(stage)）")
                : AppText.text("原生安装失败（\(stage)）：\(String(detail.prefix(160)))")
        }
    }
}

extension ToolSettings {
    /// Native installation is chosen and this build can do it.
    var usesNativeInstallation: Bool { nativeInstallation && NativeInstaller.isAvailable }
    var installationMethodTitle: String {
        usesNativeInstallation ? AppText.text("原生安装") : automaticInstallation ? AppText.text("一键安装")
            : localInstallation ? AppText.text("本机证书") : AppText.text("代理服务")
    }
}

/// Finds the port of this device's remote pairing service. The system picks it
/// at boot and advertises it over Bonjour; it is not fixed.
enum RemotePairingPort {
    private final class Search: @unchecked Sendable {
        private let queue = DispatchQueue(label: "app.local.iPadn.remote-pairing-port")
        private var browser: NWBrowser?
        private var connection: NWConnection?
        private var continuation: CheckedContinuation<UInt16?, Never>?
        private var loopbackChosen = false

        func run(timeout: TimeInterval) async -> UInt16? {
            await withCheckedContinuation { continuation in
                queue.async {
                    self.continuation = continuation
                    self.start()
                    self.queue.asyncAfter(deadline: .now() + timeout) { self.finish(nil) }
                }
            }
        }
        private func start() {
            let parameters = NWParameters.tcp
            parameters.includePeerToPeer = true
            let browser = NWBrowser(for: .bonjour(type: "_remotepairing._tcp", domain: "local."), using: parameters)
            self.browser = browser
            browser.browseResultsChangedHandler = { [weak self] results, _ in
                guard let self, self.continuation != nil else { return }
                // Other devices on the network advertise the same service;
                // this device's own record is the one seen on loopback.
                let services = results.filter { if case .service = $0.endpoint { return true }; return false }
                let own = services.first { $0.interfaces.contains { $0.type == .loopback || $0.name.hasPrefix("lo") } }
                guard let chosen = own ?? (services.count == 1 ? services.first : nil),
                      self.connection == nil || (own != nil && !self.loopbackChosen) else { return }
                self.loopbackChosen = own != nil
                self.connection?.cancel()
                let connection = NWConnection(to: chosen.endpoint, using: parameters)
                self.connection = connection
                connection.stateUpdateHandler = { [weak self, weak connection] state in
                    guard let self, let connection, self.connection === connection else { return }
                    switch state {
                    case .ready, .waiting, .preparing:
                        if case .hostPort(_, let port) = connection.currentPath?.remoteEndpoint, port.rawValue != 0 {
                            self.finish(port.rawValue)
                        }
                    default: break
                    }
                }
                connection.pathUpdateHandler = { [weak self, weak connection] path in
                    guard let self, let connection, self.connection === connection else { return }
                    if case .hostPort(_, let port) = path.remoteEndpoint, port.rawValue != 0 { self.finish(port.rawValue) }
                }
                connection.start(queue: self.queue)
            }
            browser.stateUpdateHandler = { [weak self] state in
                if case .failed = state { self?.finish(nil) }
            }
            browser.start(queue: queue)
        }
        private func finish(_ port: UInt16?) {
            guard let continuation else { return }
            self.continuation = nil
            browser?.cancel(); connection?.cancel()
            continuation.resume(returning: port)
        }
    }

    static func resolve(timeout: TimeInterval = 4) async -> UInt16 {
        let found = await Search().run(timeout: timeout)
        InstallLog.shared.add("remote pairing port: " + (found.map { "\($0) (discovered)" } ?? "\(NativeInstaller.fallbackPort) (default)"))
        return found ?? NativeInstaller.fallbackPort
    }
}
