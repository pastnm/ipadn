# iPadn 2.1.0 (31)：基于 b29 的本机更新

## 上游和基准

上游为 v2.1.0，提交 dd36a11fd8e37ac290362ca10078b74fb18efb4a。用户已确认 b29 在更换有效配对文件后「检查连接」正常；旧记录导致 InvalidHostID，不应据此把 TLS 后端认定为故障原因。

本次从已交付 b29 源码包恢复基准，再将其 iOS 16 修复移植到 v2.1.0。NativeInstall 全部文件及 Swift NativeInstaller.swift 与 b29 逐字节一致，包含依赖清单、锁文件、legacy lockdown、VPN 接口绑定和动态服务端口处理；未引入 b30 的 TLS provider / verifier 改动。对应 SHA-256 证据随构建日志交付。

保留上游 v2.1.0 新增的历史版本图标与 IPA 大小、日期筛选、下载卡片交互、原生自动安装队列与后台/实时活动、本机应用详情等功能。上游自动安装仍依赖用户预先开启相应设置、完成配对并保持 LocalDevVPN 连接。

## 本地兼容修复

- 保留 b29 的传统证书配对与 RPPairing 格式区分，iOS 16 使用传统 lockdown、62078 和已选定的 10.7.x.x utun。后续动态服务端口继续绑定同一接口，接口消失时失败。
- 保留「安装设置」帮助链接的中文片段编码，避免旧系统 `URL(string:)` 返回 nil 后强制解包。上游 v2.1.0 第 121 行仍包含未编码的地址；已在其现有 Issue #83 补充原因和修复建议：
  https://github.com/mengangs/ipadn/issues/83#issuecomment-6862214647
- 保留主程序 iOS 16.0、扩展 iOS 16.1 最低版本，以及 Widget containerBackground 的 iOS 17 版本判断；不以移除扩展代替修复。
- v2.1.0 新增的 `ActivityViewContext.isStale` 在当前 SDK 中要求 iOS 16.2。为两处显示增加兼容属性：iOS 16.2+ 保留上游行为，iOS 16.1 使用现有任务标题。首次编译发现的两处 availability 错误已修复并重新完整编译。
- 本机应用列表保留上游新增的主线程隔离与详情行为，同时沿用 b29 的 legacy listing 能力，不重新加回 iOS 17.4 的硬性门槛。
- 保留稳定文件排序和全 IPA / Mach-O 校验；主程序和扩展均为 2.1.0 (31)，应用标识仍为 app.local.iPadn 和 app.local.iPadn.LiveActivity。

## 实际验证

- 本机 Xcode 16.4（16F6）、iPhoneOS 18.5 SDK 完整 Release / arm64 编译成功；NativeInstall、Mac PKG、Unicorn、SAPRuntime、Widget / 实时活动均保留。
- Rust 19 项主机测试通过，包含本机回环 IP_BOUND_IF、动态服务端口复用、接口消失不回退与原有安装结果校验。
- Python 31 项路径排序与 Mach-O 校验器回归通过；工程与 runtime smoke 检查通过。
- XCTest / UI 测试工程 build-for-testing 成功。没有执行本轮 iOS XCTest，也没有将上游声称的 162 项运行结果算作本地测试结果。
- IPA ZIP、版本、标识、组件、运行资源哈希和全部嵌入 Mach-O 最低版本通过校验。
- 既有模拟器执行曾受 DTServiceHub 故障、当前 macOS 与 iOS 16.4 runtime 不兼容影响；本次没有重复已知失败的模拟器执行。
- 仍有上游 Swift 并发兼容警告、C 未使用函数警告及 AppIntents 元数据处理消息；未验证 Siri 快捷指令。

## 验证边界

b31 尚未在用户的 iOS 16.3.1 真机启动或执行安装。b29 的检查连接成功不能代替新版本的安装与数据保留验证；本机编译、静态检查和主机测试同样不证明真机原生安装已完成。

保留 b29 意味着保留其已知的 idevice TLS 对端证书/握手签名验证欠项；本次按用户要求维持连接基准，未将 b30 的安全实现替换进来。不要把本次编译表述为认证安全审计通过。

交付包未签名，沿用原有 TrollStore 安装方式。同一 Bundle ID 用于更新；未读取配对数据库、使用 Apple 账户、修改 VPN、重新配对或操作用户设备上的安装。本次只向上游现有 Issue 提交了不含凭据的技术评论，没有推送源码或发布 Release。

建议升级后先确认版本 2.1.0、打开「安装设置」并检查连接；连接通过后再验证一次实际 APP 安装、App Store 识别及原有数据保留。无需因版本升级主动重新导出配对文件。

历史 docs/ios16-audit.md 和 local-b29-lockdown-transport.md 保留原始调查记录；其中旧的「未编译」状态不代表本次交付状态，以此文档和编译报告为准。
