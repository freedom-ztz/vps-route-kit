# 配置和节点

完整结构见 [三协议示例](../examples/three-protocols.json)。JSON 可提交脱敏模板，真实配置存放在仓库外。

`schema_version` 固定为 1；`address` 是客户端使用的服务器地址。监听项包含唯一 `id`、`protocol`（vision/xhttp/hysteria2）、`listen`、`port` 和 `secret` 引用。

REALITY 必须显式配置 `server_name`、`target`（主机名）及可选 `target_port`（默认 443）。目标应支持 TLS 1.3；XHTTP 需要实际验证 HTTP/2。两种 REALITY 入口使用不同 TCP 端口；不增加端口复用前置服务。XHTTP 默认 `/vrk`、stream-one，不设置 Vision flow。

Hysteria 的 `certificate` 可选：

```json
{"mode":"acme","email":"admin@example.com"}
```

或指定已存在、可由服务用户 vrk 读取的文件：

```json
{"mode":"files","cert":"/etc/my-certs/fullchain.pem","key":"/etc/my-certs/privkey.pem"}
```

ACME 域名使用监听项的 `server_name`，A 记录应直指本机，不能经普通 CDN；需要公网可达 TCP 80。每台主机只自动管理一个 HTTP-01 监听。多入口可显式复用证书文件；外部证书续期后应重启对应服务。ACME 缓存不随普通配置更新删除。

## 规则

```json
{
  "default":"local",
  "rules":[
    {"domain":["api.example.com"],"action":"node:remote"},
    {"suffix":["example.net"],"action":"local"},
    {"cidr":["192.0.2.0/24"],"action":"reject"}
  ]
}
```

规则按声明顺序匹配。每条只能有 domain、suffix、cidr 中的一种，值为数组；domain 精确匹配，suffix 覆盖本域及其子域。默认动作必填。指定远端失败不会使用本机出口兜底。

IP/CIDR 规则匹配代理请求中的 IP 目标；不为按域名提交的请求提前解析 IP，也不依赖 TLS 嗅探重写目标。这样不会为了分流把域名解析泄漏到入口服务器。需要按域名分流时请明确列出域名规则。

## 远端节点与秘密

`nodes` 是名称到节点的映射，支持相同三种协议；节点属性包括 `protocol`、`address`、`port`、`server_name`、`secret`，REALITY 额外包含 `public_key`、`short_id`，XHTTP 额外包含 `path`。不接受递归 `via` 配置；本机地址指向本机监听的明显环路会被拒绝，跨主机拓扑仍应在部署前审查。

服务器自动生成监听所需 UUID、REALITY 密钥、short ID、Hysteria 密码。存储在 `/var/lib/vrk/secrets.json`（root、600），重复部署保持不变。`--secrets /private/node-secrets.json` 导入远端节点凭据；文件结构是 `{ "secret引用": {"uuid":"..."} }` 或 `{ "secret引用": {"password":"..."} }`。不要将此文件提交 Git。

`export --format nodes` 生成可供另一台主机引用的节点和最小认证信息。手动把导出的 `nodes` 合并进目标配置，把 `secrets` 保存为单独私有文件；出口选择仍需显式路由动作。

## 四层中转

```json
{"id":"remote-tcp-udp","listen":"0.0.0.0","port":26443,"remote":"192.0.2.20","remote_port":24443,"transports":["tcp","udp"]}
```

放入顶层 `relays` 数组。Realm 不终止 REALITY 或 Hysteria 加密。TCP 与 UDP 可以使用同一数值端口。客户端使用中转入口地址，但认证、公钥、服务名和证书仍对应落地端。

```sh
vrk export --host root@exit-host --format mihomo --output .private/relay.json \
  --name-prefix us-via-relay- --address relay.example.com --port-map '{"vision":26443,"hy2":26443,"xhttp":27443}'
```

## 客户端导出

- `mihomo`：JSON 格式的 YAML 文档，包含 `proxies`，可直接作为 Nikki 原生 file provider。
- `uri`：VLESS/Hysteria 分享链接。
- `xray --listener vision` 或 `xray --listener xhttp`：独立 SOCKS5 测试客户端。
- `hysteria --listener hy2`：官方 Hysteria 客户端配置。
- `nodes`：供本项目其他主机引用。

多台 VPS 一起使用时，增加 `--name-prefix jp-`、`--name-prefix us-`，避免节点重名。nodes 格式会同时为凭据引用增加前缀，便于安全合并；该格式前缀应使用小写 ASCII 标识，客户端格式可使用中文名称。

导出文件包含认证，权限 600。Mihomo XHTTP 导出固定 h2/stream-one，默认不启用额外复用；必须以实际使用的客户端版本验证。此命令只导出文件；双格式 HTTPS 订阅通过独立的 subscription 命令生成和发布。

端口映射的键始终使用原始监听 ID（例如 vision、xhttp、hy2），与展示名称前缀无关。导出后应验证真实出口，不能只做语法检查。

如果节点需要通过既有客户端入口建立连接，可在 Mihomo 导出中使用 `--dialer-proxy '既有入口组名'`，生成原生字段，不修改服务端，也不创建或选择该组。必须在完整客户端配置中确认组名存在、没有环路，并验证最终出口；不要引用可能再次绕回故障入口的自动组。其他格式拒绝此参数，避免静默忽略。

## 线路目录与订阅

[线路目录示例](../examples/catalog.json) 与原服务器部署 JSON 分开。`hosts` 保存服务器地址和可选 `ssh` / `jump`；`nodes` 保存原生 Mihomo VLESS-REALITY 或 Hysteria 2 节点及认证，`routes` 引用节点，并声明唯一 id、依次经过的主机 path、exit_host、exit_country（SG/JP/US/HK）与 expected_exit_ipv4。香港出口仅进入手动选择，自动回退仍按新加坡、日本、美国排序，全部不可用时拒绝外网。客户端中转通过节点的 dialer-proxy 引用另一节点 id，不接受未知引用或循环。固定服务端 TCP/UDP 转发则使用入口地址与端口、落地端认证和服务名，可独立导出为两种节点订阅。

`vrk catalog validate/plan --catalog ...` 输出不含认证的线路与共享依赖报告。`plan --previous /private/old-report.json` 比较增删和变化。多条路径共用同一落地机时只构成入口路径冗余。

每条线路可用 `acceptance.diagnosis`、`acceptance.stability` 引用相对目录的私有结果。诊断须匹配线路指纹及预期出口，并通过长连接、空闲恢复、双向传输与适用的 UDP 练习；稳定性须完成至少 1800 秒、两个目标各 60 次且无失败。verify 中的代理名称须与线路 id 相同。仅线路及实际依赖变化使旧指纹失效；无关节点变化不要求重测。旧版未绑定证据不能用于正式发布。单条失败不会使同批其他合格线路失效。

`rules` 可覆盖随包固定的 domains / cidrs 锁，每项为 HTTPS url、sha256；空内容、哈希不符或下载失败拒绝构建，不更新旧发布。默认规则来源是固定提交的 MetaCubeX/meta-rules-dat CN 域名和 IPv4 网段，更新须审查锁文件后重新构建。

可选 `dns.bootstrap/domestic/remote` 分别设置节点引导、国内与外网解析。可选 `company.domains/cidrs/dns` 设置私有公司规则；公司域名只使用显式公司 DNS、返回真实地址，不配置公共回退。公司规则优先于国内分类；公共模板不含真实公司域名。

双格式构建包含 Clash 节点源和完整配置、V2Ray Base64 URI 列表。V2Ray 客户端独立管理策略，不从 URI 获得 Mihomo 的 DNS 或国家回退。分享链接沿用落地认证和 SNI；不支持表达的客户端链明确排除，并在不含认证的 manifest 中说明。若全部节点均为客户端链，只能构建 Clash；选择 V2Ray 或双格式时拒绝空的 URI 集合。

Mihomo 1.19.32 的 provider 内节点不能直接通过名称作为 dialer-proxy；工具使用原生全局中转策略组衔接。OpenWrt 首次合并 openwrt-example.json 中的固定组；示例中的普通策略组应复用本地既有组，不直接覆盖同名对象或重命名生产组；中转组增删需要单独审查本地策略，不能只更新订阅后假定已配置。组内缺失或所有出口失败时使用 REJECT，不使用 DIRECT/COMPATIBLE 兜底。

选择 Clash 时 `--mihomo` 必填，使用指定核心做原生校验。完整配置监听回环 7890 和 DNS 1053，LAN/TUN 默认关闭；端口冲突由客户端环境处理，不自动修改系统配置。

可选 `local` 对象使用 `domains` 与 `dns` 数组，显式指定本地域名及解析器，同时生成直连和真实地址规则。仅排除 Fake-IP 不会自动发现本地 DNS。公司规则仍使用 `company` 私有配置；公开模式拒绝公司配置。

`--access-mode public` 无需 `--access-file`。`--name` 必须是项目标识符，不接受路径；固定路径只暴露所选格式和不含凭据的 `/version.json`。公开规则路径含内容版本，回滚不会把旧客户端指向新版规则。

自动回退组首项为 REJECT，用于所有成员均不健康时明确拒绝；健康线路仍按国家顺序选择。健康检查域名通过独立国内 DNS 引导解析，避免启动时等待尚未就绪的代理组；实际探测连接仍经过被测节点。
