# B35：iOS 16 安装服务查询兼容处理

此版继续使用 B29 的传统 Lockdown 配对、RustCrypto TLS 后端和 VPN 接口绑定，保留官方 v2.1.0 功能及设置闪退修复。应用版本 2.1.0 (35)，主程序最低 iOS 16.0，扩展最低 iOS 16.1。它延续 B34 的 iOS 16 适配，与只修官方设置闪退的 B33 不同。

## 本次设备证据

用户提供的 B34 / iOS16.3.1 日志中，两次都已建立 lockdown 62078 和 installation_proxy 动态端口连接，服务返回 ssl=true，TLS 客户端握手完成。Lookup 请求发送后，读取第一条响应长度头失败：query_socket io=unexpected_eof errno=0 tls=none。尚未获得任何应用查询响应，不能解释成「设备未安装该应用」。B34 当时没有记录已收到的头字节数，因此仍无法排除半截长度头。

unexpected_eof 确认读取所需数据前连接结束，但不确定关闭发生在设备服务、VPN 转发还是 TLS 对端。tls=none 只说明错误链未捕获 rustls::Error，不代表没有 TLS。errno=0 表示缺少原始系统错误号，不能解释成没有错误。诊断的 VPN on: no 与真实 utun 连通日志不同，不能凭该启发式字段判断 VPN 未连接。用户还确认 B29 目前也失败，但没有提供 B29 的具体阶段日志。

## 改动

1. 查询长度头与 XML 正文分开调用 send_raw，分别完成写入及 flush。idevice 0.1.68 的 send_plist 和 libimobiledevice property_list_service 也分别写入长度头与正文。长度仍为四字节大端，首轮请求字段完全保留，响应仍支持多帧。这是对齐兼容写法，不是确认 iOS 服务要求某种 TCP 分包；TCP 和 TLS 不保证保留应用写入边界。
2. 按实际读取统计首个长度头已接收字节数。只在传统 Lockdown 路径、第一条响应头零字节且 UnexpectedEof 时，丢弃旧安装服务连接，重新 StartService 并连接同一已选 VPN 路由上的新动态端口，再做一次只读 Lookup。
3. 第二次仅移除 ClientOptions.ReturnAttributes，不改变 ApplicationType、BundleIDs、命令或 TLS/配对参数，请求服务返回完整属性，减少字段筛选兼容性干扰。最多一次重试；已有的整体查询超时仍覆盖两次尝试。每次响应仍受 128 帧和累计 64MiB 上限约束。
4. 半截头、半截正文、后续响应 EOF、设备拒绝、畸形或缺失有效结果不重试；有效空字典才是有效空结果，不把连接故障或部分列表冒充查询成功。现代远程配对路径不使用此重试。
5. 安装/升级命令、上传、购买记录核验与安装后校验逐字节保留，没有增加安装重试。查询会在安装前/后使用，仍不能以系统 Complete 代替核验。失败提示现在明确显示连接提前结束，不声称应用不存在。

配对、TLS、VPN 的实现源码与 B34 字节一致；B29 认证和生产依赖保持原样。为真实 TLS 主机测试加入 tokio-rustls 开发依赖，它已被 Cargo.lock 间接锁定，没有升级或新增第三方包版本。测试沿用 B29 idevice 的 TLS 客户端和 RustCrypto，未引入 B30 的 ring/provider/verifier 改动。保留的原有 TLS 对端验证欠项不因此获得安全认证结论。

## 验证与边界

36 项 Rust 主机测试通过。新增覆盖：零响应 EOF 后新连接成功、目标筛选和购买元数据保留、第二次 EOF/连接失败不做第三次尝试、部分头/正文/结果/设备拒绝不重试、现代路径与无字段筛选的请求不重试。真实 localhost TLS1.2/TLS1.3 双向认证均覆盖直接查询成功，以及 TLS 正常关闭后重新建立服务连接并完成查询。测试使用公开合成身份，密钥与证书只在 cfg(test) 引入，不包含用户凭据，也不会进入设备库。

Swift 错误提示 7 组与脱敏 3 组、Python 31 项回归、工程与离线 runtime smoke 检查结果，以及完整 Xcode16.4 Release、测试工程 build-for-testing、IPA/Mach-O 核验，见随包编译报告。build-for-testing 只是编译测试包，本轮没有 iOS XCTest 执行结果或真机安装结果。

本次改动是针对已知 EOF 阶段的兼容处理，尚未确认首轮写入边界或 ReturnAttributes 是真机根因，不能把合成服务测试当作真机问题已经修复。若两次都 EOF，下一步仍需要设备端安装服务/转发信息；没有依据要求重新生成配对文件。

## 使用

保留当前 Lockdown 配对文件与 LocalDevVPN 配置，安装后确认「复制诊断信息」首行为 iPadn 2.1.0 (35)，先检查连接。若失败，提供末尾 native protocol，重点是 step=attempt、step=header_eof、step=retry、step=retry_result，以及最后错误。无需分享配对文件、证书或私钥。

检查连接通过后再验证实际 APP 安装、App Store 识别和数据保留。完整未签名 IPA 保留 NativeInstall、Mac PKG、Unicorn、SAPRuntime、Widget/实时活动，应用标识仍为 app.local.iPadn，用于覆盖更新。历史说明是调查记录，以本文件与本轮验证报告为准。没有操作系统配对数据库、修改设备 VPN/信任、自动配对、安装用户设备应用或发布上游版本。
