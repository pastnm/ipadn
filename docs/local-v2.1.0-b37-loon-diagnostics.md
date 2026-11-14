# iPadn 2.1.0 (37)：Loon 接口诊断版

## 当前证据

用户已确认 B36 在 iOS16.3.1 使用 LocalDevVPN 时“连接正常”。提交的日志同时证明：`utun9#33 source=10.7.1.1` 上 Lockdown TCP、心跳 TLS、首次 Marco/Polo、installation_proxy TLS 和 Lookup Complete 均成功。实际 APP 安装和覆盖更新尚未收到成功验收。

Loon 下相同 B36 报 `route=none / tcp=interface_unavailable`，失败阶段为 `lockdown_route`，尚未连接 Lockdown，也未进入配对、TLS 或心跳。截图插件声明 `include-tun = 10.7.0.1/32`、`ipv6-vif = off`、IP Rewrite reflect。Loon 文档说明 include-tun 只控制指定目标是否进入 TUN，不会要求接口自身地址属于10.7网段；功能要求实际 Loon Build1007及以上。截图展示的是插件最低版本要求，不能据此确认用户安装的 Loon 版本或插件是否实际生效。

B36 的接口筛选要求活动 IPv4 utun、有效索引、源地址和目标均为 RFC1918 私有地址、源地址与10.7.0.1前两个字节相同、源地址不同于目标。Loon 的实际接口地址尚未采集；“Loon接口被过滤”是待验证的主要方向。

## B37 范围

B37 增加诊断，保留 B36 的接口筛选和已验证连接实现。B36 的配对解析、TLS、绑定连接、心跳、应用查询、上传、安装/升级、购买元数据和安装后验证代码保持。不会把诊断探测成功的被过滤接口用于认证。这一版本用于查明 Loon 差异，不宣称修复 Loon 连接。

诊断仅针对本机既有目标 `10.7.0.1:62078`：

1. 列出实际 IPv4 枚举中的 utun 名称、索引、源IPv4及原B36筛选结果；另外尽力采样未进入候选枚举的关闭/IPv6-only隧道。IPv6仅记录是否存在，物理网卡IP、MAC、SSID和IPv6具体地址均不写入诊断。每次最多24条接口记录，附汇总和截断数。
2. 获取 UDP connect 的内核本地源地址提示，不调用发送。只有匹配已枚举utun时输出其地址；其他地址隐藏为non_utun_or_unknown。该提示不是路由表查询，也不是TCP可达性或指定接口承载流量的证明，日志明确标记 `proof=source_only`。它不影响认证路径，限时300毫秒。
3. 仅当B36没有合格路由时，对最多4个不同索引的活动IPv4 utun执行绑定TCP握手探测。目标固定，每个上限1200毫秒；总探测等待最多约4.8秒，不进行LAN扫描。禁止对物理网卡、无效索引、环回/组播/未指定源地址和源等于目标的条目探测。
4. 探测socket在结果记录前关闭，无应用层写入、TLS、plist或配对凭据。不会返回给认证客户端，也没有TCP无绑定回退。有合格LocalDevVPN路由时不执行这类探测，继续沿原逻辑连接。

辅助接口状态和源提示失败只记录固定错误类别与errno；不会阻止原有合格路由。实际认证接口枚举失败仍按原代码报错。没有增加第三方依赖或功能版本，没有读系统配对数据库、修改信任/VPN或操作设备安装。

## 如何测试

用原有签名方式覆盖安装完整未签名IPA，确认诊断首行为 `iPadn 2.1.0 (37)`。

1. 断开LocalDevVPN，确认Loon实际版本达到3.5.3(1007)，回环插件启用，保存并重连Loon。
2. 保持设备解锁，在iPadn点一次“检查连接”。B37保留B36筛选，Loon下仍可能显示相同错误；本次目的是采集诊断。
3. 立即从“账号 → 设置 → 维护 → 复制诊断信息”复制末尾本次Installation server log。发送包含 `phase=route_diag` 的全部行，以及最后的连接结果；不要发送配对文件、证书或私钥。一次结果通常足够，反复操作会挤出旧日志。

示例为合成值，不代表实测Loon地址：

```text
native protocol: phase=route_diag step=policy target=10.7.0.1 source_prefix=10.7 rule=b36
native protocol: phase=route_diag step=interface route=utun8#32 source=198.18.0.1 up=true eligible=false reason=source_not_private
native protocol: phase=route_diag step=summary ipv4_utun=1 eligible=0 omitted=0
native protocol: phase=route_diag step=source_hint method=udp_connect sent_bytes=0 source_hint=utun8#32 source=198.18.0.1 proof=source_only
native protocol: phase=route_diag step=probe_summary candidates=1 max=4 timeout_ms=1200 auth=not_sent
native protocol: phase=route_diag step=probe route=utun8#32 source=198.18.0.1 target=10.7.0.1 port=62078 elapsed_ms=2 tcp=connected errno=0 auth=not_sent
native transport: route=none port=62078 tcp=interface_unavailable errno=0
native request failed at lockdown_route
```

## 结果解释

| 结果 | 可以得出的结论 |
| --- | --- |
| eligible=false，source_not_private或source_prefix_mismatch，且同接口probe tcp=connected | B36地址筛选排除了一个可建立TCP的接口；下一步可做受控兼容适配，但尚未证明配对、心跳或动态服务端口兼容 |
| 没有活动IPv4 utun，或只有no_ipv4/interface_down | 当前枚举中无可用IPv4隧道，先核实Loon连接、插件及实际版本 |
| 有被过滤utun，但probe超时/拒绝/系统拒绝 | 不只是地址筛选证据；应结合Loon回环配置、端口和系统权限继续定位 |
| eligible=true，但原连接失败 | 看原route=...行的连接错误，诊断不会改走其他认证路径 |
| 原连接进入heartbeat、app_query阶段 | 接口筛选和Lockdown TCP已通过，按后续服务结果排查 |

源地址提示仅作补充，不能独立证明故障点。多utun时若探测达到4个或日志omitted非0，仍可能需要进一步采集；不能把单个失败结果解释为所有隧道都不支持。

## 验证与限制

51项Rust主机测试通过，含7项新诊断测试：原B36规则与原因、down/IPv6-only记录、隐藏和日志上限、源提示性质、固定目标和次数/索引限制、真实绑定TCP零数据与关闭、接口消失时无无绑定回退、诊断追加后原错误阶段和连接socket可用性。B36全部心跳、mTLS和安装元数据相关测试继续通过。

构建和审计细节见交付报告。B37未在用户真机上执行；XCTest仅编译，不宣称已运行。此前B36的LocalDevVPN连接成功属于用户反馈与提交日志证据，不等同于B37的真机验收。App Store识别、实际安装和覆盖更新仍需设备验证。
