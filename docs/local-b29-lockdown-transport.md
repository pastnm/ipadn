# b29：iOS 16 lockdown 的 VPN 接口绑定修复

## 证据与范围

b28 的 `lockdown_connect` 提示发生在初始 TCP 建连阶段；此时还没有开始 StartSession/TLS。不能据此认定配对记录无效。用户报告 LocalDevVPN 已连接，Tunnel IP 为 10.7.1.1/32，Device IP 为 10.7.0.1/32；本地网络列表中没有 iPadn。缺少列表条目本身不能证明权限被拒绝。

核对用户提供的 b28-lockdown-diagnosis.md 与本机 iCTRL 修复源码后，确认 iCTRL 的 IPv4 服务连接支持 IP_BOUND_IF，而 iPadn b28 的普通 TcpProvider 没有绑定接口。该差异是优先验证的修复方向，尚不能证明它是本次真机故障的唯一原因。

## 实现

- iOS legacy 路径仅使用固定的本机 VPN 目标 10.7.0.1:62078；从当前活动 IPv4 utun 接口中选择 10.7.x.x 的候选，不硬编码 utun 编号。两个 /32 地址可以位于不同 /24，不因 10.7.1.1 与 10.7.0.1 不在同一 /24 而排除。
- 每个候选用 IP_BOUND_IF 在真实 socket 上尝试 TCP；选择后直接复用该 socket 开始 lockdown 会话。候选探测阶段不发送配对记录。
- 选定的接口名、索引和本地 IPv4 地址保存在同一 provider 中；后续 AFC / installation_proxy 的动态端口使用该 provider。每次连接前检查接口仍存在且处于活动状态。接口消失时失败，不自动改走 en0、任意远程地址或未绑定的 socket。
- 接口名/索引/地址、目标端口、耗时、errno 和固定 ErrorKind 分类传回 Swift，进入现有诊断导出。错误日志不输出 io::Error 的任意载荷、PairingFile Debug、证书或私钥。提示区分缺少接口、权限拒绝、连接拒绝、无路由和超时。
- 保留配对格式预检、原有 StartSession/TLS、设备身份检查、原生安装功能、现代远程配对分支、Widget/实时活动和 Mac PKG。未加入自动重新配对或自动修改 VPN。
- 主程序和扩展 build 同步增为 29；应用标识不变。新增 libc 直接依赖使用 Cargo.lock 已有的 0.2.191，其他依赖版本不变。

## 验证与限制

Rust 主机测试 19 项通过，其中包含真实回环 socket 的 IP_BOUND_IF 读取确认、实际 provider 在多个服务端口上的路由复用、消失接口不回退，以及错误脱敏。Swift 主机错误文案检查 6 项通过。这些是本机回环和纯逻辑测试，不是 iOS 16 设备连接测试。

工程与资源校验、Python 路径排序测试 3 项及 Mach-O 校验器测试 28 项通过。完整 Release IPA 与 XCTest 工程均使用本机 Xcode 16.4 编译；最终结果和哈希见随包编译报告及 build-info.json。

本次未重新运行已知受 DTServiceHub 握手故障阻塞的模拟器测试；`build-for-testing` 成功仅代表测试工程编译成功，不代表 XCTest 已运行。当前 macOS 不支持已安装的 iOS 16.4 runtime，未运行 iOS 16 模拟器测试。

未连接用户设备、读取设备配对数据库、修改设备 VPN、重新配对或执行应用安装。需要用户使用新包依次验证 TCP、StartSession/TLS、StartService、动态端口及查询 iPadn 自身；检查连接仍失败时导出诊断，不先重复配对或重置网络。

已知限制：iOS legacy 候选限定为 10.7.x.x utun，不支持自定义其他地址段，也未加入本机 Wi-Fi 地址回退。活动 utun 的 TCP 可达性不等同于验证 VPN 提供方身份。b28 审计记录的 idevice TLS 对端证书/握手签名验证欠项仍存在；本次没有修改或验证其认证机制，不能把连接修复或编译通过表述为原生安装已经安全可用。
