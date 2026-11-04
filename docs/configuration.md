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

导出文件包含认证，权限 600。Mihomo XHTTP 导出固定 h2/stream-one，默认不启用额外复用；必须以实际使用的客户端版本验证。不安装订阅 HTTP 服务。

端口映射的键始终使用原始监听 ID（例如 vision、xhttp、hy2），与展示名称前缀无关。导出后应验证真实出口，不能只做语法检查。

如果节点需要通过既有客户端入口建立连接，可在 Mihomo 导出中使用 `--dialer-proxy '既有入口组名'`，生成原生字段，不修改服务端，也不创建或选择该组。必须在完整客户端配置中确认组名存在、没有环路，并验证最终出口；不要引用可能再次绕回故障入口的自动组。其他格式拒绝此参数，避免静默忽略。
