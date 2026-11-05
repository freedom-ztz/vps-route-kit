# 诊断与测试

`vrk status` 查看管理的服务；`doctor` 查看待恢复事务、绑定及基础依赖；`logs` 从 journald 读取并隐藏秘密存储中已知的认证值。日志脱敏不保证能识别第三方输出中的所有隐私，不应直接公开原始日志。

## 常见问题

- **端口冲突**：检查 `ss -lntup`。项目拒绝停止其他软件；选择经过审查的不同端口。
- **ACME 失败**：核对 A 记录、CAA、TCP 80、云安全组和 CA 限速。不要关闭证书校验。
- **服务 active 但外网不通**：active 只代表进程存在。用导出客户端验证认证、TLS、目标访问和最终出口。
- **中转节点证书错误**：检查是否保留落地端 SNI/认证；不能因为连接地址变成中转机就把服务名改成中转 IP。
- **指定远端不可用**：预期明确失败。不要增加本机出口兜底来掩盖问题。
- **公司网络无法直连测试 VPS**：分别记录直连失败与经已有入口成功的结果，不能混为同一条路径。

## 性能测试

先记录测试端到本地网关的丢包与时延；无线抖动明显时，用同网段有线客户端作对照，并分别记录接口、平台与核心构建。不要把终端环境差异直接归因 VPS，也不能以 Linux 客户端通过代替 Mac 客户端通过。

测速端点由使用者明确指定，不内置付费服务。以下 URL 是公开 Cloudflare 测速端点示例：

```sh
vrk benchmark --proxy socks5h://127.0.0.1:10808 \
  --down-url 'https://speed.cloudflare.com/__down?bytes=25000000' \
  --up-url 'https://speed.cloudflare.com/__up' \
  --rounds 3 --output /private/benchmark.json
```

每轮请求下载 25 MB、上传 8 MB。记录 HTTP 状态、curl 退出码、字节数、耗时和速度；中位数只统计完整成功样本。单连接结果不等同于 Speedtest 多连接。可通过 `--cpu-host root@exit-host --jump root@jump-host` 对远端核心进行 /proc CPU 计时采样，输出以单核 100% 为基准的平均占用；未指定时 CPU 标记为未测。采样失败单独记录，不推断为零占用。

## 发布前验收

- 配置规则语义、凭据稳定、导出、哈希失败、恢复启停状态：单元测试。
- 官方锁定核心解析生成配置：Linux CI；需要从官方 GitHub 下载核心。
- 三协议的 TCP/UDP、实际证书、HTTP/3 页面、远端出口、中转：真实测试机。
- 重复 apply、错误配置、不可达远端、拒绝规则、服务和系统重启、卸载后恢复、升级失败：真实测试机。
- 连续 30 分钟，每 30 秒一次 HTTPS；长连接另测。保留失败样本，按路径分别判断，不把复测覆盖原失败。

CI 不连接私人 VPS，不使用真实凭据，也不保证某个运营商网络可用。未经实际验证的平台或协议组合须在发布记录中注明。

## 可追溯网络验收

`vrk verify --cases /private/cases.json --output /private/new-run.jsonl` 读取[清单示例](../examples/verification.json)。先替换受控目标 URL 和本地代理地址；目标必须是允许只读检查的 HTTPS 入口。客户端应为每条路径使用独立、固定的本地监听，测试期间不要切换共享代理组。

默认 60 轮、间隔 30 秒，同时检查受控服务与公共目标；可以声明独立旧节点作为对照。它不修改 VPS、OpenWrt 或客户端网络设置，不重试后覆盖第一次失败，也不因某条路径不可达就自动排除。

- JSONL 逐项保存 curl 原始退出码、HTTP 状态、连接/TLS/首字节耗时和本地端口；本地端口可与代理核心日志关联。使用本地 SOCKS 时，`time_connect` 仅是连接本地监听的耗时，不能当作入口 RTT；入口 TCP 连通性由 `audit` 单独检查。原始入口探测与代理请求出现矛盾时单独记录，需核对路径和发生时刻，不能直接判为持续的入口故障。
- 强制使用显式代理，忽略环境变量 NO_PROXY，避免把直连当作代理成功。
- 不记录响应正文或完整业务 URL，不自动猜测“线路故障”还是“项目缺陷”；`proxy_or_transport` 必须结合核心日志及对照实验判断。
- 输出文件权限为 600，拒绝覆盖已有结果；中断时保留样本和 `completed: false` 的汇总。
- 汇总位于 `<输出路径>.summary.json`。`active_cases_passed` 表示实际执行用例的结果；有人工说明的 excluded 项时，`all_declared_passed` 仍为 false，命令返回非零。不能把排除坏路径后的结果称作全部通过。

需要诊断失败时，同时保存独立测试核心的日志。仅凭 curl 的 SSL_ERROR_SYSCALL 不能确定目标网站 TLS 出错：代理节点建连被核心取消，也可能表现为这个错误。测速命令现在也保存错误原因与 TLS 阶段耗时，并强制使用指定代理。

## 分段诊断及连接练习

### 受控端点与整批验收

`python3 -m vrk.probe_server --listen 127.0.0.1 --cert /private/cert.pem --key /private/key.pem` 提供临时 HTTPS 18446 与 UDP 回显 18445。公网监听必须显式设置地址并检查端口，测试后停止；它不提供订阅或代理服务。TLS 握手超时为 10 秒，握手后连接超时为 120 秒；慢握手在独立线程中处理。`/metadata` 声明下载、上传、流式响应和超时参数。启动后先验证证书、端点长度、同一连接空闲 30 秒复用与 UDP 原样回显，保存带校验值的自检收据，再进行节点测试。

`vrk audit --catalog /private/catalog.json --cases /private/audit.json --output /private/new-batch` 要求清单覆盖全部线路。阶段依次为逐节点连接与 DNS 对照、全部节点三轮测速、逐节点会话诊断、最后 30 分钟稳定性观察。抓包和资源采样先写入被测服务器本地，测试结束后再取回，避免 SSH 实时日志占用被测链路；采集器启动失败须先修复或明确记为缺失证据。大流量与稳定性测试不重叠；一个节点失败不会阻止其他节点或跳过该节点测速。测速不能开始时也保存失败样本，不能填成 0 Mbps 或当作未执行。会话清单必须包含持续响应、空闲复用和双向传输；声明支持 UDP 时还必须提供 UDP 练习，缺失项目会在联网前拒绝。UDP 能力使用预先登记的独立主机回显，禁止将访问出口宿主机自身的结果推广为普通 UDP 出站能力。

DNS 对照在正常域名请求之外使用 `connect_ip`：通过 curl `--connect-to` 固定连接 IP，保留原域名 SNI 与证书校验。对照差异只能提示解析相关问题，仍须结合出口服务器 DNS 证据与嗅探配置归因。测速也支持 `--connect-ip`。每个测速样本记录开始、结束时间与是否完整传输；成功样本中位数和所有轮次完整后的中位数分开，超时样本不会被静默删除。单次超时不自动归因为运营商或协议识别。

整批清单包含 `routes`、`targets`、`evidence`、`stability`、`fixture_controls`；每条线路明确 `proxy`、`pinned_target`、`egress_url`、`exercise`、`benchmark` 和只读配置核对的 `configuration` 收据。夹具控制收据必须包含 `passed: true` 并匹配 SHA-256。输出保留每条原始样本、来源配置、工具与目标摘要、阶段完成状态。只有全部要求实际完成才标记合格；传输失败与工具异常分别记录。不要把稳态通过、压力测试和真实业务登录混为一个结论。

`vrk diagnose --catalog /private/catalog.json --cases /private/diagnosis.json --output /private/new-result.json`，参考 [诊断清单](../examples/diagnosis.json)。每条线路明确固定代理监听、只读 HTTPS 目标、返回实际源 IPv4 的受控 egress_url。分段检查由 local 或配置了 SSH 的 host 发起；缺少权限标记未测，不自动认定线路或项目故障。UDP 分段只支持受控 echo，不用“发送 UDP 未报错”判断端口可达。

可在每条诊断用例增加 exercise：stream_url/stream_seconds（默认 30）、idle_url/idle_seconds（默认 30）、download_url/upload_url、udp（host/port/size，默认 1200）。必须使用受控目标：stream 持续响应，idle 返回 204 并保持 HTTP keep-alive；下载返回恰好 25 MB，上传允许恰好 8 MB；UDP 原样回显。上传是显式启用的测试行为，不向业务接口猜测发送请求。

idle 与 UDP 需要 socks5h 监听；空闲测试要求复用同一 TLS 连接，不能以重新连接成功冒充长连接保持。并行传输、持续响应及 UDP 分别保留结果；诊断不记录正文、完整 URL 或代理凭据，结果权限 600，不覆盖旧文件。出口 IP 请求另存 `egress_probe`，保留首次 curl 退出码、错误、HTTP/TLS 耗时和本地端口；解析不到地址时仍保留失败证据，响应正文不落盘。

## 订阅交付验收

分别检查 Clash 完整配置、OpenWrt 节点源与 V2Ray Base64 解码结果。用实际客户端版本验证协议，不把 URI 解析成功当作实际登录或 GUI 导入通过。V2Ray 核心与 v2rayN 客户端不是同一组件；Hysteria 需客户端提供对应核心，REALITY/XHTTP 也有版本要求。

`python3 scripts/validate_delivery.py --mihomo /path/to/mihomo` 使用本机 HTTP/SOCKS 测试夹具和真实 Mihomo 核心，验证两条模拟新加坡线路均失效后切到日本、美国，全部失效拒绝，以及 provider 的 404、超时、空内容、无效内容、节点删除、缓存重启和无缓存首次启动。报告明确标为 simulation，不代表真实国家线路已验收。CI 固定下载并校验 Mihomo 1.19.32 的 Linux amd64 兼容构建，适用于未暴露 x86-64-v3 指令集的虚拟机；不安装代理服务。

真实 VPS 另验 HTTPS 证书、令牌撤销、发布回滚、静态服务重启、代理 PID 不变，以及 UDP/长连接和 30 分钟观察。生产 OpenWrt 本轮只核对配置，不做节点源切换；真实 OpenWrt 生产刷新与重启验收留待独立维护窗口，不能以独立 Mihomo 进程测试冒充。

## 可发布证据

`verify` 清单增加可选 `evidence`：`catalog`（私有目录绝对路径）、`batch_id`（本次唯一批次）、`core_versions`（实际测试的核心版本映射）。`diagnose` 清单使用相同 evidence，且每条路线的 targets 与 verify 一致。verify 的代理名称必须匹配线路 id。

诊断及稳定性文件都保存绑定：线路与依赖指纹、批次、核心版本、目标摘要。正式构建要求二者绑定相同，诊断整体完成、出口匹配，且该线路两个目标各至少 60 次无失败、完整观察不少于 1800 秒。保留其他失败路线和总报告，逐条选择合格线路。core_versions 应来自实际运行版本记录，不能根据节点名称猜测。

回归检查包括不完整诊断、旧稳定性记录、新节点影响范围、重复发布、切换前校验、HTTPS 检查失败恢复、并发部署回滚冲突、独立格式构建，以及公开固定路径与内容版本规则。真实 GUI 导入、VPS 运行测试和受控模拟结果分别记录，不互相替代。

正式发布还要求诊断包含成功的 stream、idle、download、upload 练习；声明 UDP 能力的节点还要求 udp 成功。仅 HTTPS 页面可达不能取得正式发布资格。
