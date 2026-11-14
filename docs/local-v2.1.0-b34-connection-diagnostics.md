# 第二版：继续修复与连接诊断（B34）

此版在 B32 上继续，保留官方 v2.1.0 功能、安装设置闪退修复、最低 iOS 16 兼容，以及用户指定的 B29 配对、RustCrypto TLS 后端和 VPN 接口绑定。没有引入 B30 的 provider/verifier 改动。版本号为 2.1.0 (34)。

## 最新真机证据

B32 在 iOS 16.3.1 上三次均已连通 utun9#33 的 lockdown 62078 与 installation_proxy 动态端口，发送查询请求后，在读取第一条响应的四字节长度头时返回 query_socket。未读到任何响应 plist，多响应结果处理还未开始。errno=0 表示 io::Error 未携带原始系统错误号，不能认定没有错误。旧版将 EOF、InvalidData 等统一显示为 socket_error，无法据此确定服务关闭、网络中断还是 TLS 报错。

用户随后确认：切回 B29，使用同一份有效配对文件和 LocalDevVPN，现在也失败。尚未收到 B29 的具体阶段日志，因此不能确认两版原因相同；这一对照说明故障不只发生于 B32。诊断里 Proxy or VPN on: no 是弱启发式结果，与实际 utun TCP 连通记录不一致，不能单凭该字段判定 LocalDevVPN 已断开。

## 本版改动

- 增加 io::ErrorKind 固定分类，例如 unexpected_eof、invalid_data、connection_reset、broken_pipe；保留实际 errno（缺失时为 0）。
- 从嵌套错误链识别 rustls 错误，以固定类别或 IANA alert 数字记录，不输出任意服务端文字、证书、配对内容或私钥。tls=none 只说明没有捕获到 rustls 错误对象，不能证明连接未使用 TLS。
- 记录安装/AFC 服务的系统返回端口、ssl 标志，以及 TLS 握手开始、成功或失败。握手成功后首次读取仍可能报错，不能仅凭 tls_ready 排除之后的 TLS 错误。
- 保留 B32 的多响应查询处理、失败不冒充「未安装」和查询错误提示；B34 不改变查询参数、字节格式、超时、TLS 握手调用或配对选择。

这是诊断构建，尚未确认或修复本次真机连接失败的具体根因。不要把增加错误信息视为已解决设备问题。本轮未更改设备 VPN/信任设置、读取系统配对数据库、重新配对或安装到设备。

## 验证与使用

31 项 Rust 主机测试通过，新增覆盖首个响应头前关闭、半截响应头 EOF、嵌套 TLS alert 与错误信息脱敏。Swift 提示 6 组和脱敏 3 组通过；Python 31 项回归通过。完整 Xcode Release 编译、工程与运行资源 smoke、IPA/Mach-O 检查和 XCTest build-for-testing 结果见交付报告。本轮未执行 iOS XCTest 或真机安装。

NativeInstall、Mac PKG、Unicorn、SAPRuntime、小组件和实时活动完整保留；应用最低 iOS 16.0，扩展最低 iOS 16.1。B29 原有 TLS 对端验证限制仍存在，不把本次构建作为认证安全审计结论。历史 docs 中 B29/B31/B32 的状态仅供追溯，以本说明和当前编译报告为准。

更新后确认版本为 2.1.0 (34)，保持目前有效配对文件和 LocalDevVPN 配置，解锁设备后检查连接。如仍失败，复制末尾的 native protocol（包含 phase=service、phase=app_query 和 io=/tls=）以及 native request failed 即可；无需提供配对文件、证书或私钥。没有必要仅因本轮更新主动重新配对。

B33 与 B34 的应用标识相同，安装会互相覆盖。B33 保留官方安装逻辑，B34 保留 B29 的 iOS 16 原生安装适配；两个包的目的不同。
