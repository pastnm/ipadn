# iPadn 2.1.0 (38)：已观察 Loon 回环接口兼容

## 已确认的阻断点

用户的B37真机日志在iOS16.3.1上两次检查均显示：

```text
08:22:25 / 08:22:40
phase=route_diag step=interface route=utun9#33 source=198.19.0.1 up=true eligible=false reason=source_not_private
phase=route_diag step=summary ipv4_utun=1 eligible=0 omitted=0
phase=route_diag step=source_hint method=udp_connect sent_bytes=0 source_hint=utun9#33 source=198.19.0.1 proof=source_only
phase=route_diag step=probe route=utun9#33 source=198.19.0.1 target=10.7.0.1 port=62078 elapsed_ms=1 tcp=connected errno=0 auth=not_sent
native request failed at lockdown_route
```

这证明当前Loon隧道接口具有IPv4地址198.19.0.1，在该接口上绑定TCP能连通既有目标10.7.0.1:62078；iPadn随后仍按B36规则拒绝该接口。198.19.0.1属于基准测试保留地址，Rust的is_private不将其归为RFC1918私有地址，因而被过滤。即使单独移除该检查，旧规则要求源地址前两个字节与10.7.0.1相同，也仍会阻断。

已确认的是应用自身的接口筛选阻断和该接口上的TCP可达性。B37探测没有发送配对凭据，尚未验证Loon上的Lockdown认证、心跳、动态安装/AFC服务或实际APP安装。源地址提示只是辅助信息；关键TCP证据来自实际绑定接口的连接。

B36此前在LocalDevVPN上已由用户确认“连接正常”，提交日志也显示心跳和应用查询完成。实际安装/覆盖更新仍未收到成功反馈。

## B38 实现

在保留B36原有地址规则的基础上，只增加以下已观察组合：

- 枚举到启用的IPv4 utun，接口名必须为utun加数字，索引非0。
- 接口源地址恰好为198.19.0.1，目标恰好为10.7.0.1。
- 继续将Lockdown、心跳、installation_proxy和AFC的真实socket绑定到选中的同一接口；每次连接仍检查接口是否存在。服务端口按原流程由Lockdown返回，不硬编码动态端口。

不放开整个198.18.0.0/15或任意私有/公网地址。如果同时存在原B36合格接口和新增Loon接口，先按原有顺序尝试B36接口，后尝试新增接口。不会增加无绑定认证回退或其他目标发现。

配对文件格式/解析、HostCertificate和HostPrivateKey使用、RustCrypto/TLS实现及既有TLS预检、同一原始Lockdown会话、Marco/Polo首次应答门槛和心跳生命周期、应用查询和只读重试、上传、安装/升级、购买元数据及安装后验证均保留。没有增加生产依赖、功能或第三方版本。Swift只更新过时的路由错误说明，使其提示LocalDevVPN或Loon回环，并引导复制诊断；不会将路由失败提示为重新导入配对文件。

B37诊断保留，接受的接口增加policy标记，并记录选中策略：

```text
phase=route_diag step=policy target=10.7.0.1 source_prefix=10.7 extra_source=198.19.0.1 rule=b38
phase=route_diag step=interface route=utun9#33 source=198.19.0.1 up=true eligible=true reason=accepted policy=loon_reflect
phase=route_diag step=selection policy=loon_reflect
route=utun9#33 source=198.19.0.1 port=62078 ... tcp=connected
phase=service name=heartbeat step=start
phase=heartbeat step=ready polo=1
phase=app_query step=response ... status=complete result_dictionary=true
```

这是预期流程示例，B38尚无用户真机结果。有合格Loon接口时，B37的“被过滤接口TCP探测”会跳过，直接以该真实绑定连接进入原有认证；若后续配对/TLS/心跳/服务失败，明确报告该阶段，不自动重配对或安装重试。所有诊断隐藏规则和上限保留。

## 验证

55项Rust主机测试通过，含4项新增策略测试：精确允许已观察映射及拒绝相邻/其他地址、对照原B36筛选的输入矩阵验证旧行为保留、保留原顺序并优先B36接口、Loon接受日志和跳过被过滤探测。原有绑定真实socket、接口消失时无无绑定回退、诊断零应用数据、TLS1.2/TLS1.3双向认证、心跳生命周期和安装元数据测试继续通过。

B36/B37的接口枚举、绑定连接、路由连接选择函数、认证和完整安装实现通过字节比较保留。新增候选排序和固定selection日志为入口的预期差异。工程/runtime/Python/Swift、完整Release和IPA/Mach-O检查结果见交付报告。XCTest为build-for-testing，未执行用户设备连接或安装。

## 使用与验收

用原方式签名覆盖安装B38完整IPA，确认诊断首行为iPadn2.1.0(38)。保持当前配对文件和Loon回环配置，断开LocalDevVPN，连接Loon并解锁设备，先点一次“检查连接”。

若成功，再试装一个APP，验证打开及App Store识别；覆盖更新另核对原有数据。若失败，立即复制本次Installation server log，从phase=route_diag到最终阶段即可。不要发送配对文件、证书或私钥。Loon实际版本应满足回环功能要求的3.5.3(1007)及以上。

没有操作系统配对数据库、修改用户信任/VPN配置、安装用户设备应用或发布到上游。原B29的对端证书验证限制保留；本版没有将TCP探测成功等同于认证或安装成功。
