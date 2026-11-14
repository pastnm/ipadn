# iPadn 2.1.1 (39)：同步上游并保留 B38 VPN 连接

上游主线 b8eaa07fc1f78881ace1c8be8c97362db49dcc7c，正式版 v2.1.1 的代码提交 c4052f41506ff8e0d5412dd953eaca1c96dfccfe。两者仅 AltStore 发布信息不同。与上次基准 dd36a11 相比，上游未修改 NativeInstall 或 NativeInstaller.swift。

## 为什么提示“旧格式”

官方 2.1.1 的 validatePairingFile 看到 HostCertificate 或 DeviceCertificate 就直接提示“这是旧格式的配对文件”，仅接受 RPPairing。该判断在 2.1.0 已经存在，不是这次更新让原有文件失效，也不是已检查到文件过期。

| 项目 | 传统 lockdown 配对 | RPPairing 远程配对 |
| --- | --- | --- |
| 典型内容 | HostCertificate、DeviceCertificate、HostPrivateKey、HostID、SystemBUID 等证书和主机信息 | public_key、private_key（各32字节）、identifier 等远程配对信息 |
| 本版连接入口 | lockdown 62078，再按设备返回连接动态服务端口 | 远程配对服务、RSD/隧道 |
| 本版系统分支 | iOS16至17.3使用此方式；有效传统文件在更新系统上也保持该协议 | iOS17.4及以上的远程配对分支 |
| 能否改扩展名转换 | 不能 | 不能 |

两者来自不同的配对过程，不能只改文件名、扩展名或字段完成转换。对于用户原有 iOS16 环境，保留 B38 的传统配对和 VPN 连接即可，不需要生成 RPPairing 文件。有效配对文件可继续使用；更改设备信任关系、还原后或明确认证失效时才需重新导出。文件含敏感密钥，请勿上传。

## B39 同步内容

- 上游设置页安全帮助链接：显式编码中文片段，使用可选 URL，避免强制解包；同步 URL 回归测试和帮助入口的可访问性标识。
- 上游 App Store 查看和分享链接容错；无法构造 URL 时省略不可用入口。
- 上游历史版本日期范围筛选面板、大字体适配和对应界面测试。
- 完整保留 B38 的传统/RPPairing 解析、TLS、心跳、应用查询、上传、安装升级、购买元数据和安装后核验；NativeInstall 全目录、NativeInstaller.swift 和构建脚本逐字节比对，29项文件一致。未混入 B30 TLS 改动。
- 保留 LocalDevVPN 原筛选优先级及 B38 的 Loon 已观察映射：活动 IPv4 utun 源198.19.0.1到目标10.7.0.1。真实 lockdown、心跳和动态服务 socket 继续绑定同一接口，接口消失不改走无绑定认证。
- 版本2.1.1(39)，保持 app.local.iPadn 及扩展标识，主程序最低iOS16.0、扩展16.1；NativeInstall、Mac PKG、Unicorn、SAPRuntime、小组件和实时活动均保留。

## 使用

用原有签名/安装方式覆盖更新 B39；确认版本2.1.1(39)，保持原来有效的配对文件和 B38 VPN/回环配置，先检查连接，成功后再验证实际 APP 安装。更新本身不需要重新配对。

本轮不读取或修改用户配对数据库、信任关系、VPN设置、账号或设备安装。主机测试和本机编译不等于用户设备实测；本次没有运行用户设备连接/安装。完整测试与 IPA 证据见同目录编译与验证报告。原 B38/B29 的 TLS 对端验证限制继续保留。
