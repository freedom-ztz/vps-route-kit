# 诊断与测试

`vrk status` 查看管理的服务；`doctor` 查看待恢复事务、绑定及基础依赖；`logs` 从 journald 读取并隐藏秘密存储中已知的认证值。日志脱敏不保证能识别第三方输出中的所有隐私，不应直接公开原始日志。

## 按症状定位故障

按“客户端 → 入口 → 中转/落地 → 目标”排查，先证明测试工具正常，再归因 DNS、配置或线路。结论分为已确认、证据支持和原因未确定；不能因为换节点后恢复就认定原协议被识别，也不能把所有 HTTPS 失败都算成 DNS。

| 症状 | 优先取得的证据 | 修复或下一步 |
| --- | --- | --- |
| 核心未启动、`Illegal instruction` | 版本、架构、CPU 标志、二进制 SHA-256 与进程退出码 | 选锁定且匹配 CPU 的官方构建；没运行的请求记未执行，不算线路失败 |
| `active` 但无法代理 | 核心日志、监听、UUID/公钥/short ID、SNI、目标 HTTPS 与出口 | 核对实际加载配置；端口冲突停止部署，不杀其他服务 |
| `226/NAMESPACE` | systemd 日志、挂载源文件、权限及 unit 路径 | 修正声明配置/生成器；保持事务恢复，不加启动补丁 |
| 域名失败、固定 IP 成功 | 同一时段域名与固定 IP 对照、服务命名空间 DNS 请求和回答 | 查 resolver 指向、UDP/TCP DNS、上游 TLS；按[DNS 隔离方案](deployment.md#vps-dns-部署与隔离)最小范围修复 |
| 宿主机解析正常、容器/服务失败 | 容器 DNS 或实际进程 namespace 的 resolver | 修该消费者，不直接覆盖全局 DNS；容器回环不是宿主机回环 |
| Unbound SERVFAIL / TLS 验证失败 | 时间、CA、信任锚、DoT 服务名、TCP 853 与审计日志 | 修上游/信任/权限；不关闭 DNSSEC、CA、AppArmor 或增加明文回退 |
| REALITY/XHTTP 间歇约数秒失败 | 客户端首次错误、服务端 DNS、外层握手及请求接受日志 | `connect error` 不能区分原始 TCP、TLS 或服务端解析；证据不足则保持未确定 |
| 节点已改名，fallback 仍显示 REJECT，但组内节点健康 | `GET /proxies` 中该组的 `fixed` 是否仍指向不在 `all` 列表中的旧名称 | 在面板取消该组固定，或通过原生 `DELETE /proxies/<URL编码组名>` 取消固定；保留有效选择，不清空整个 cache.db、不重启 DNS |
| 中转证书或认证错误 | 入口端口映射、落地公钥/认证/SNI、证书链与有效期 | 保留落地身份；不使用跳过证书校验解决中转问题 |
| TCP 上传可完成、下载超时 | 双向完整字节、TCP 重传/RTT/拥塞窗口、CPU 与直达/中转对照 | 可判传输退化；定位到具体段前不调整 MTU、窗口、拥塞算法或归因运营商 |
| UDP 发出但无回复 | 同时段两端接收/发送记录、独立回显、方向、NAT/云及系统防火墙 | 发包成功不是可达；只修有证据的阻断规则，不清空防火墙 |
| Hysteria 中转慢、TCP 正常 | 官方客户端在中转机直测落地、环回正对照、独立跨机回显 | 区分中转配置与 UDP 接收方向退化；换协议不代表根因已修复 |
| Hysteria 初始握手超时 | 官方客户端启动日志、SOCKS 是否已监听 | 未打开 SOCKS 前就失败记“上游握手失败”；后续 HTTPS 记未执行，不能计成本地连接拒绝 |
| Hysteria 跑久后失败、新客户端恢复 | 原客户端状态、同时段新旧核心、版本/构建、UDP/资源统计 | 非同时对照不能区分会话状态与线路恢复；不以定时重启充当修复 |
| 多国家同秒延迟或终端测速上下行悬殊 | 客户端到网关、同 LAN 受控传输、有线对照、其他负载 | 先排除共享接入瓶颈；无线正常信号强度不证明链路没有性能问题 |
| 401/403、挑战页或业务拒绝 | 实际响应码、TLS、目标/资源域名与合法会话状态 | 分开记录网络可达和应用可用，不把 HTTP 返回当超时或完整业务通过 |
| ACME 或到期证书失败 | A/CAA、TCP 80、签发/续期日志、真实证书与核心读取权限 | 修证书路径及续期条件；不占用已有网站或关闭 TLS 验证 |

锁定版本 [Mihomo 的 XHTTP 连接处理](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/adapter/outbound/vless.go)在同一 connect-error 包装中包含传输与 TLS 建连；curl 的 SSL 错误可能只是上游失败的外在表现。其[核心拨号期限](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/component/dialer/dialer.go)独立于 curl 总超时，增大测速请求超时不能证明核心的握手窗口已改变。按实际版本核对，不把该结论推广到所有版本或协议。

### 只读检查与证据归属

以下在对应 VPS 上执行，域名替换为实际故障目标；`dig`/`openssl` 需事先安装。服务内 DNS 视图检查见[部署指南](deployment.md#项目服务通过-service_dns-接入)。

```sh
getent ahostsv4 example.com
dig example.com A +time=2 +tries=1
dig example.com AAAA +tcp +time=2 +tries=1
# 验证真实目标的证书、TLS 1.3 和协商结果；XHTTP 检查是否返回 h2
timeout 10 openssl s_client -connect example.com:443 \
  -servername example.com -verify_hostname example.com \
  -verify_return_error -tls1_3 -alpn h2 </dev/null
ss -ti
nstat -az
systemctl show vrk-xray -p MainPID -p InvocationID -p NRestarts
```

分别在失败前后取 `nstat` / 资源快照，累计计数不是本次连接独有的故障数。抓包必须覆盖预期网卡及方向；按地址、端口、连接序列与核心日志关联，存在采集掉包、时钟不确定或缺少一端证据就注明。中转服务也可能修改源地址，不能只查客户端源 IP。原始日志、域名、包元数据和配置快照保存在受控目录，不直接贴到公开 Issue。

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

分段记录将 SSH／进程执行总耗时 `elapsed` 与实际连接或回显耗时 `probe_seconds` 分开，并保存远端相对本机的时钟偏移上下界；不假设 SSH 往返延迟对称。关联多机抓包和核心日志时先核对时差，优先按连接地址、端口和 TCP 序列号匹配，不能只比较日志时间。时钟跳变会使偏移记录标记为不可比较；探测进程未成功执行时标记未测，不算目标线路故障。工具不会校准系统时钟。

离线 DNS 抓包按记录中的观测结束时间计算等待时长，不能使用分析时的当前时间。采集末尾尚未等满观察期限的查询标为观测未完成，不能判为超时；采集结束记录中的掉包数是累计值，不再与中间统计相加。未见 DNS 回复、解析错误和完整业务访问失败分别记录，不互相替代。

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

## 修复后的复验与退出条件

1. **冻结基线。** 记录源提交、核心版本及 SHA-256、配置摘要、路径、预期出口、客户端接口、测试目标、服务 PID/InvocationID、主机时差和原始失败。工具或夹具自检失败时先修工具，补测使用新批次，不覆盖旧证据。
2. **一次只改一类问题。** DNS、监听认证、证书或端口映射分别修复；同时保留一个已验证入口。改 DNS 后同时查服务内 resolver 与主机原文件校验值，确认修改范围；不同时升级核心、调 MTU 或修改路由。
3. **连接与出口。** 检查正常域名及固定 IP 对照、真实认证/TLS、最终出口 IP；失败的出口请求保留原始错误，不写成“出口 IP 不匹配”。固定 IP 对照保留 SNI 和证书校验，不能用 `-k` 取得通过。
4. **完整传输及会话。** 同一客户端、端点和参数，每条三轮下载 25 MB、上传 8 MB；记录尝试次数、完整字节及耗时，另测持续响应、同连接空闲恢复、并行传输和适用的独立 UDP 回显。成功样本的峰值不能替代三轮完整样本的中位数。
5. **稳定性。** 不与大流量测试重叠，连续至少 1800 秒、每 30 秒一轮，受控 HTTPS 和公共目标各至少 60 次。修 DNS 后仍有连接异常就分别记录，DNS 正常不等于整条线路合格。短时重新启动客户端后成功不能消除原失败。
6. **保留故障并清理。** 按线路和检查类型分别计算失败比例；不要把握手一次失败后跳过的所有练习都当成独立网络失败，也不要用失败节点删除后的统计冒充全量通过。未通过者移出正式交付，按用户决定保留测试候选或删除；删除节点不抹去历史证据。归档取回校验 SHA-256 后，清理本批临时监听、进程和采集文件，保留原服务及受控备份。

修复确认至少同时具备“变更确实生效”和“相应故障未再观测到”的证据。线路仍失败而诊断不足时交付原因未确定，不通过反复切换、扩大超时或周期重启制造通过。单个公共目标异常先与变更前及受控目标比较，不能反复回滚/重启正常服务。

不同客户端、接口、构建或不同时段的速度不可作为严格 A/B 提速结论。Linux 虚拟机通过不能代替 Mac Wi-Fi 通过，配置解析成功也不能代替 GUI 导入或实际连接。宿主机重启、生产网关接入与应用登录应独立授权和记录；不在独立客户端测试中顺带修改 OpenWrt、公司 DNS/DHCP 或出口策略。

订阅返回 Cloudflare 1010 时，先对照客户端真实 `User-Agent`。Python urllib 默认请求头被拒绝，不代表 Mihomo/v2rayN 的订阅请求失败；项目规则下载使用明确的 `vps-route-kit/版本` 标识并继续校验 TLS 与 SHA-256。验证实际客户端的 200 响应、产物哈希及非挑战内容，不能仅为消除工具误报关闭全站浏览器检查。参考 [Cloudflare 1010 说明](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1010/)。

生产配置做语义差异比较时使用 YAML 1.2 解析器；YAML 1.1 可能把未加引号的 `off` 当成布尔值，而 `find-process-mode` 需要枚举字符串。候选先用目标机器上的实际核心校验，确保除节点与策略组外的 DNS、规则、端口等未发生类型或取值变化。
