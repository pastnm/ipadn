# iPadn 2.1.0 (36)：传统网络安装服务心跳

## 依据与边界

B35 的 iOS16.3.1 日志表明：62078 和动态安装服务端口 TCP 均连通，TLS 报告 ready，但 Lookup 的首个响应头接收到 0 字节后 EOF。分开写长度头/正文、仅移除 ReturnAttributes 的一次兼容重试均失败。这不是应用不存在或配对文件失效的证据；日志中的 `tls=none` 仅表示未提取到 rustls 错误类别。

固定依赖 idevice 0.1.68 的 [heartbeat.rs](https://docs.rs/idevice/0.1.68/src/idevice/services/heartbeat.rs.html) 明确说明：没有运行并应答的心跳客户端时，iOS 会关闭服务连接。B29 至 B35 的传统安装路径均未启动该服务。

本机此前的 iCTRL iOS16 修复曾观察到 heartbeatd 撤销服务连接，并在补充首次 Marco/Polo、保留原 Lockdown 会话后恢复镜像服务查询。该记录是相关历史证据，服务类型不同；它不能证明当前 iPadn 的 EOF 必然同因。B36 尚待用户真机验收。

## 实现

1. 按原 B29 流程解析用户导入的配对文件、选择并绑定 VPN 路由、StartSession、核对可选 UDID。
2. 在这条已认证的 Lockdown 上仅启动一次 `com.apple.mobile.heartbeat`。动态端口仍经同一 provider，按设备返回值启用原 TLS；不调用会另外建立 Lockdown 会话的 `HeartbeatClient::connect`。
3. 等待第一次 Marco 并写出 Polo 后才标记 ready，再启动 installation_proxy / AFC。首个 Marco 等待上限15秒；Polo 写入上限5秒。后续等待采用设备间隔加5秒，饱和处理并限制在5至60秒。
4. 心跳任务由本次操作拥有，在查询、上传、安装/升级、安装后核验期间持续回复。查询和受监控 I/O 在心跳中断时立即报错，新服务建立前后均检查存活状态；不把查询失败转为“未安装”。
5. 完成时先尽力 StopSession，然后 abort 并 join 心跳任务。初始化失败、取消、超时或丢弃会话也会 abort，避免普通 JoinHandle 丢弃后后台连接仍存活。正常关闭记录 stopped；异常丢弃依靠任务取消释放套接字，不伪造正常关闭日志。

保留 B35 受限只读查询兼容重试，仍只允许首个响应头0字节 EOF 后新开服务再查一次。心跳中断不触发它。安装和升级不新增重试；如安装期间心跳丢失，结果未知，保留可能仍被系统读取的暂存包并提示先核实应用状态。购买元数据、安装/升级请求、App Store 识别和安装后验证逻辑保留。

仅开启已固定 idevice 的 heartbeat 功能；没有增加第三方版本或生产依赖包。配对格式、HostCertificate/HostPrivateKey、RustCrypto backend、TLS预检和 VPN 绑定保留。B29 既有对端证书验证限制也仍存在。

## 诊断

固定分类日志只包含阶段、端口、状态和计数，不包含配对文件、证书、私钥、设备返回正文或应用清单：

```text
phase=service name=heartbeat step=start
phase=service name=heartbeat step=selected port=… ssl=…
phase=heartbeat step=wait_first
phase=heartbeat step=ready polo=1
phase=service name=installation_proxy step=start
phase=heartbeat step=polo count=2
phase=heartbeat step=stopped
```

失败阶段为 `heartbeat_setup` 或 `heartbeat_lost`。原因使用固定类别 sleep / timed_out / socket / tls / invalid_message，或既有服务建立阶段；不输出原始错误字符串。后续成功心跳只记录第2、3次，避免长时间安装产生无界周期日志。

## 验证

44 项 Rust 主机测试通过，包括8项新增心跳测试：首次应答门槛、持续应答、畸形/睡眠/EOF/取消处理、任务与套接字清理、间隔溢出边界、中断后禁止新命令和停止在途等待、目标服务建立失败后的清理。

其中 localhost 集成测试使用真正绑定接口的 TCP 和既有 idevice/RustCrypto 双向 TLS1.2、TLS1.3，模拟同一原始 Lockdown 上先开一次心跳、再开一次安装服务；设备收到首次和后续 Polo 后才返回查询结果。另验证心跳中断时查询停止、无兼容重试、无第二次 StartSession。测试中 Lockdown 端点模拟为已认证会话；服务 TLS 为真实握手。这些模拟不等同于 Apple 设备兼容性验证。

完整构建、工程/Python/Swift/runtime 检查和 IPA 审计结果见交付报告；XCTest 仅 build-for-testing，不宣称已执行。没有操作用户设备、系统配对数据库或信任/VPN 设置。

## 真机验收

使用现有签名工具安装 B36 未签名完整 IPA，诊断首行应为 `iPadn 2.1.0 (36)`。保持当前有效配对和 LocalDevVPN 设置，设备解锁后先“检查连接”。如仍失败，复制从 `name=heartbeat` 到最终错误的诊断记录即可，无需发送任何配对凭据。若检查成功，再验证实际 APP 安装及安装后 App Store 状态。
