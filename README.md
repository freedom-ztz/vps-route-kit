# VPS Route Kit

使用 JSON 配置、中文菜单和 `vrk` 命令，部署并维护 VPS 代理入口、固定中转和服务端出口分流。适合自行管理少量 VPS；无需管理面板、常驻管理进程或内核补丁。

## 功能

| 能力 | 实现方式 |
| --- | --- |
| VLESS + REALITY + Vision | Xray，TCP，`xtls-rprx-vision` |
| VLESS + REALITY + XHTTP | Xray，HTTP/2、`stream-one`，不设置 Vision flow |
| Hysteria 2 | 官方核心、有效证书、standard BBR、自适应带宽、本地 HTTP/3 静态网页 |
| 固定 TCP / UDP 中转 | Realm 转发到指定落地机，不终止代理认证和加密 |
| 服务端分流 | 有序匹配精确域名、域名后缀、IP/CIDR，选择本机出口、指定远端节点或拒绝 |
| 部署与恢复 | 差异预览、候选配置、原子切换、受影响服务重启、失败回滚、备份及显式版本升级 |
| Clash / V2Ray 订阅 | Clash Meta/Mihomo 完整配置与节点源、V2Ray Base64 链接列表，使用标准 Nginx 静态 HTTPS 发布 |
| 客户端导出 | Mihomo/Nikki file provider、VLESS/Hysteria URI、独立客户端配置、供其他 VPS 引用的节点 |
| 诊断与验收 | 状态、脱敏日志、基础诊断、固定代理测速、保留首次失败的 JSONL 网络验收 |

固定核心版本：Xray 26.5.9、Hysteria 2.13.0、Realm 2.9.6。官方地址与各架构 SHA-256 记录在 [版本锁](vrk/versions.lock.json)，下载保持 TLS 和完整性校验，不自动跟随 latest。

## 架构与部署场景

### 单机落地

```text
客户端 / OpenWrt → Vision / XHTTP / Hysteria 2 → VPS 本机出口 → 目标网站
```

一台 VPS 即可运行。按需保留入口，首次可只部署一个。三种入口使用同一台机器的出口；配置多个协议不会自动产生多个国家 IP。

### 固定四层中转

```text
客户端 → 中转机 Realm → 落地机协议入口 → 落地机出口 → 目标网站
```

中转机仅配置固定转发，不需要落地入口的 UUID 或密码。客户端使用中转地址和端口，但公钥、UUID/密码、SNI 和证书身份仍对应落地机。这条路径不增加额外代理加密，两个网络段都必须可用。

### 入口分流到不同出口

```text
客户端 → VLESS 入口 ──────────────────→ Xray 路由 → 本机出口
       → Hysteria 入口 → 回环 SOCKS5 ─→           → 指定远端节点 → 目标
                                                  → 拒绝
```

入口终止客户端代理连接，再按目标选择出口。远端 VLESS 使用 Xray 原生出站；远端 Hysteria 使用官方客户端的回环 SOCKS5 桥接。仅启动实际被引用的远端服务。所有监听共享主机级路由，指定远端不可达时明确失败，不改成本机出口。

这里的 `local` 指当前 VPS 的出网路径，不是客户端绕过代理直连。CIDR 匹配请求中提供的 IP，不会先把域名解析成 IP 再分类；域名分流应明确填写域名规则。

### 与 OpenWrt 的分工

| 位置 | 管理范围 |
| --- | --- |
| 本项目 / VPS | 协议服务、固定中转、服务端出口规则、节点导出、部署与恢复 |
| OpenWrt / Nikki / Mihomo | 透明代理、公司和国内直连、客户端 DNS、国家优先级与自动回退 |
| 主路由 / AP | 上游网络、网线与 Wi-Fi 接入 |

桌面完整配置默认按新加坡、日本、美国自动回退，香港出口仅供手动选择，外网代理全部失效时拒绝直连。OpenWrt 的这些规则继续由本地策略组管理。本项目不生成完整路由器策略，也不接管 DHCP/DNS。新电脑即插即用依靠 LAN 正确下发网关和 DNS，部署 VPS 不能代替这部分配置。

## 环境与准备

| 项目 | 要求 |
| --- | --- |
| 管理电脑 | Python 3.11+；SSH 远端操作需要系统 SSH；测速与网络验收需要 curl。macOS 支持管理、校验和导出 |
| VPS | Debian 12 / Ubuntu 24.04，amd64 / arm64，运行 systemd，具备 Python 3.11+、CA 证书、iproute2、util-linux、用户管理工具及 tar |
| 权限 | 本机部署以 root 执行；远端使用 root SSH 或等价 root 登录，工具不自动 sudo。不保存 SSH 密码，不关闭主机身份校验 |
| 连通性 | 客户端到入口、入口到落地、落地到目标分别可达；服务器可通过 HTTPS 下载 GitHub 官方发行包 |
| REALITY 参数 | 显式提供 `server_name`、`target` 和可选目标端口；从 VPS 检查目标 TLS 1.3，XHTTP 还需验证 HTTP/2 |
| Hysteria 证书 | 内置 ACME 或已有有效证书；ACME 需域名、仅 DNS A 记录、邮件、允许签发的 CAA 和空闲且公网可达的 TCP 80 |
| 私有目录 | 仓库外存放每台主机实际配置、远端认证、客户端导出和备份 |

REALITY 入口可以直接使用 VPS IP 作为连接地址，不需要自己的入口域名或证书。Hysteria 的域名必须匹配有效证书；普通 CDN 代理不可代替这里的 UDP 入口。ACME 由 Hysteria 自动续期，项目不接收 DNS 账户凭据；已有证书则由外部维护续期和相应服务重载。

在受支持的 Debian/Ubuntu VPS 上，可按需以 root 安装基础依赖：

```sh
apt-get update
apt-get install -y python3 ca-certificates iproute2 util-linux passwd tar
ss -lntup
```

默认仅列出防火墙需求，不修改系统规则或云安全组。示例端口如下，可在配置中显式修改；冲突时停止，不停止其他服务或自动换端口：

| 用途 | 端口 | 范围 |
| --- | --- | --- |
| SSH | 已有 SSH TCP 端口 | 管理机或跳板可达 |
| Vision | TCP 24443 | 客户端或中转机可达 |
| XHTTP | TCP 25443 | 客户端或中转机可达 |
| Hysteria 2 | UDP 24443 | 客户端或中转机可达 |
| ACME HTTP-01 | TCP 80 | 公网可达，续期时仍需可用 |
| Realm 示例 | TCP/UDP 26443、TCP 27443 | 使用中转的客户端可达 |
| SOCKS5 内部桥接 | 回环 18080、18100 起 | 仅本机，不向公网放行 |

## 快速开始

### 1. 安装管理命令

在管理电脑获取源码并安装；确认 `python3` 为 3.11+，管理机具备 venv/pip：

```sh
git clone git@github.com:freedom-ztz/vps-route-kit.git
cd vps-route-kit
python3 -m venv .venv
.venv/bin/pip install .
export PATH="$PWD/.venv/bin:$PATH"
vrk --version
```

后续也可直接使用 `.venv/bin/vrk`。更新源码后重新安装，才能更新 venv 中的命令；从源码目录可以直接执行 `python3 vrk.py`。运行时无 Python 第三方依赖。

先通过系统 SSH 登录目标主机并核实指纹。私钥、SSH 端口和 ProxyJump 复用 `~/.ssh/config`，也可给远程命令加 `--jump root@jump-host`。远程执行临时上传工具并在结束时尝试清理，不安装常驻管理进程。

### 2. 生成并编辑配置

```sh
mkdir -p "$HOME/.config/vps-route-kit"
chmod 700 "$HOME/.config/vps-route-kit"
vrk init --output "$HOME/.config/vps-route-kit/server.json"
```

默认生成三个入口，示例地址必须修改后才能部署：

1. 把 `address` 改为实际连接的 VPS IP 或主机名。
2. 在 `listeners` 保留需要的协议，填写正确的 REALITY 参数或 Hysteria 域名及证书信息。首次只测 Vision 时删除其余两个监听。
3. 首次保留 `nodes: {}`、`relays: []`、`routing: {"default":"local","rules":[]}`，先验证单机落地。
4. 需要远端出口时再配置 `nodes` 和独立私有认证文件。字段、规则及证书格式见 [配置说明](docs/configuration.md)。

本机入口的 UUID、REALITY 密钥和 Hysteria 密码由工具首次生成并保存在 VPS，重复部署保持不变。实际配置和认证不要提交 Git。

### 3. 预览并部署

```sh
vrk validate --config "$HOME/.config/vps-route-kit/server.json"
vrk plan --config "$HOME/.config/vps-route-kit/server.json" --host root@my-vps
# 审查差异、确认端口和备份后执行
vrk apply --config "$HOME/.config/vps-route-kit/server.json" --host root@my-vps
vrk status --host root@my-vps
vrk logs --host root@my-vps
```

`validate` 检查字段与引用；`plan` 比较声明配置和版本，不生成凭据、不下载核心、不激活服务，也不代表完整预检。`apply` 检查环境与端口、下载并核对核心、生成候选配置、原子切换、重启受影响服务并检查进程与监听；失败恢复上一状态。

已有网站占用 TCP 80 时，使用明确配置的已有证书；工具不修改 Nginx。项目只管理自己的服务，不覆盖已有 Xray 或 Docker 配置。多台主机分别执行，没有跨主机事务。

### 4. 导出并独立验收

```sh
vrk export --host root@my-vps --name-prefix test- \
  --output "$HOME/.config/vps-route-kit/provider.json"
vrk export --host root@my-vps --format xray --listener vision \
  --output "$HOME/.config/vps-route-kit/client-vision.json"
```

导出文件包含认证，权限为 600。Mihomo 文件只有节点，不会自动导入客户端或设置策略组；Xray/Hysteria 独立配置需自行使用兼容核心运行。先验证实际连接、证书、目标 HTTPS 和最终出口，再增加中转或分流。中转导出的地址和端口映射见 [配置说明](docs/configuration.md#四层中转)。

复制 [验收清单](examples/verification.json) 到私有目录，填写已运行客户端的固定本地代理地址、受控目标和预期响应码后执行：

```sh
vrk verify --cases "$HOME/.config/vps-route-kit/cases.json" \
  --output "$HOME/.config/vps-route-kit/first-run.jsonl"
```

每条路径使用独立监听，测试期间不切换共享组。`verify` 不启动客户端、不自动检查出口国家、不以重试覆盖首次失败，排除项不会算作全量通过，结果文件不可覆盖。详细指标和测速方法见 [测试与排障](docs/testing.md)。

## 订阅与 OpenWrt 接入

订阅格式和接入方式分别选择：

| 产物 | 内容 | 使用位置 |
| --- | --- | --- |
| `desktop.json` | Clash Meta/Mihomo 完整配置：节点、DNS、国内直连、国家回退 | 桌面客户端直接导入完整订阅 |
| `nodes.json` | Clash Meta/Mihomo 节点集合 | OpenWrt 原生 HTTP proxy-provider；也可供已有客户端策略使用 |
| `v2ray.txt` | Base64 编码的多行 VLESS/Hysteria 分享 URI | v2rayN 等兼容客户端；分流、DNS 和回退由客户端自身负责 |
| `openwrt-example.json` | provider、策略组和必要的中转引用示例 | 审查后合并到 OpenWrt 本地配置，不是完整网关配置 |

“Clash”指 Clash Meta/Mihomo；旧版 Clash 不支持所有协议。“V2Ray 订阅”指分享链接格式，不代表原始 V2Ray 核心支持 REALITY/XHTTP/Hysteria。客户端必须具备对应核心与协议支持，版本兼容性应实际验证。

V2Ray 链接可以表达直达和 Realm 四层中转，不能表达客户端 `dialer-proxy` 链。构建时明确列出被排除的链式节点；若没有可表达的节点，则拒绝双格式构建，不发布空订阅。Clash 中的链式节点需要配套固定中转策略组，首次接入须合并示例；此后更新节点不改网关策略。

线路目录独立于单机部署配置，见 [脱敏示例](examples/catalog.json)。每条线路声明入口路径、出口国家、预期出口和共享服务器依赖。正式构建要求匹配的诊断、出口和 30 分钟稳定性证据；测试候选须显式使用 `--include-candidates`，发布也须加 `--allow-candidates`。

```sh
vrk catalog plan --catalog /private/catalog.json
vrk diagnose --catalog /private/catalog.json --cases /private/diagnosis.json --output /private/diagnosis-result.json
vrk subscription build --catalog /private/catalog.json --output /private/release-1 \
  --base-url https://sub.example.com:18443 --access-file /private/access.json --mihomo /path/to/mihomo
vrk subscription publish --bundle /private/release-1 --publish-config /private/publish.json \
  --access-file /private/access.json --host root@web-host
```

生成的私有令牌文件确定链接前缀：`https://源站/令牌/desktop.json`、`/nodes.json`、`/v2ray.txt`。工具不把完整链接打印到终端。静态站点使用现有 Nginx 二进制、独立配置和独立 systemd 单元，不运行订阅 API；不修改已有网站或代理服务。

桌面完整配置更新会替换其中策略；长期修改应保存在私有生成配置。OpenWrt 只更新节点源，继续维护本地 DNS、公司直连和 DHCP。两种场景都需要首次能够访问订阅地址；节点源默认独立直连下载，受限网络可显式指定已有的独立管理入口，避免依赖尚未加载的节点组。

字段、证据及链式节点见 [配置说明](docs/configuration.md)，发布和撤销令牌见 [部署恢复](docs/deployment.md)，兼容性及故障测试见 [测试说明](docs/testing.md)。

## 日常维护

| 操作 | 命令 |
| --- | --- |
| 中文菜单 | `vrk menu --config server.json --host root@my-vps` |
| 修改配置 | 编辑源 JSON → `vrk plan` → `vrk apply` |
| 状态、日志、基础诊断 | `vrk status`、`vrk logs`、`vrk doctor` |
| 节点导出、网络验收、测速 | `vrk export`、`vrk verify`、`vrk benchmark` |
| 备份与回滚 | `vrk backup`、`vrk rollback` |
| 显式升级与卸载 | `vrk upgrade`、`vrk uninstall` |

`backup` 输出远端私有归档路径，需自行 SCP 取回；含秘密和证书，不可公开。`rollback` 恢复同一主机的项目快照和服务状态；卸载默认保留秘密、证书和备份。菜单调用同一套命令，配置仍用 JSON 编辑。

| 文件或目录 | 归属 |
| --- | --- |
| 管理机仓库外的 JSON / 认证 / 导出 | 操作者维护的私有源文件 |
| `/opt/vrk/bin/` | 校验后的官方二进制及下载收据 |
| `/var/lib/vrk/` | 生成配置、持久凭据、证书缓存、部署历史和备份 |
| `/etc/systemd/system/vrk-*.service` | 项目管理的原生服务 |

不要手改生成文件。重复部署、自动恢复的边界、防火墙、证书及升级操作见 [部署与恢复](docs/deployment.md)。

## 支持与验证范围

第一版使用 IPv4、主机级路由，不提供多用户计费、Web 面板、自建订阅 API、后台规则更新或服务端国家自动回退。指定远端失败不隐式直连。

0.2.0 增加线路目录、双格式静态订阅和分段诊断；软件回归与真实线路可用性分别验收。Debian 12 amd64 已验证三协议和中转的实际出口。Ubuntu 24.04、arm64 尚未完成真实机验收。已配置 GitHub Actions，不表示远端 CI 已运行。

测试网络仍有 UDP 回程不可达和间歇建连异常，整体稳定性门槛尚未通过；功能连接成功不等于生产可用。项目不承诺某个协议必然提速或无法识别。测试应分别记录 TCP/UDP、证书、实际出口、故障行为与稳定性，原始私有结果不随源码发布。

## 开发与贡献

```sh
python3 -m pip install '.[dev]'
black --check vrk tests scripts vrk.py
python3 -m unittest discover -s tests -v
python3 scripts/check_public.py
# Linux：下载固定官方核心并校验生成配置
python3 scripts/validate_cores.py
# 显式指定 Mihomo 1.19.32，运行受控模拟，不连接私人 VPS
python3 scripts/validate_delivery.py --mihomo /path/to/mihomo
git diff --check
```

源码：`vrk/cli.py` 为命令入口，`config.py` 校验配置，`render.py` 生成核心配置，`deploy.py` 管理部署事务，`remote.py` 管理 SSH，`export.py` 导出节点，`verification.py` / `diagnostics.py` 执行验收与诊断，`catalog.py` / `subscription.py` / `publishing.py` 管理线路及订阅交付。测试在 `tests/`，脱敏配置在 `examples/`。

提交 Issue 或 PR 时提供脱敏后的环境、步骤、预期和结果；行为修改附相关回归测试。不要提交真实 IP/域名、凭据、证书、节点导出、备份或业务日志。发布前审查暂存差异，自动检查无法识别所有隐私。

## 许可与参考

源码采用 [Apache-2.0](LICENSE)。核心不随项目分发，各自遵循上游许可证。

- [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent)：参考多协议管理的功能设计，没有复制其 AGPL 源码或安装脚本。
- [Xray-core](https://github.com/XTLS/Xray-core)、[官方配置](https://xtls.github.io/config/)、[XHTTP 讨论](https://github.com/XTLS/Xray-core/discussions/4113)。
- [Hysteria](https://github.com/HyNetworks/hysteria)、[服务端配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)。
- [Realm](https://github.com/zhboner/realm)：固定四层转发。
- [Mihomo](https://wiki.metacubex.one/config/proxies/transport/)：客户端导出接口。
- [v2rayN 订阅说明](https://github.com/2dust/v2rayN/wiki/Description-of-subscription)：标准分享链接及订阅格式。

## 固定订阅链接

支持公开固定路径或带令牌的私有路径，默认仍使用令牌。公开模式会允许任何人下载节点凭据；不要加入公司配置。示例：

```sh
vrk subscription build --catalog /private/catalog.json --output /private/release \
  --name builder --formats clash,v2ray --access-mode public \
  --base-url https://sub.example.com --mihomo /path/to/mihomo
```

公开地址为 `/clash/builder.yaml`（桌面完整配置）、`/clash/providers/builder.yaml`（OpenWrt 节点源）、`/v2ray/builder.txt`（Base64 URI）。可单独选择 `--formats clash` 或 `--formats v2ray`；V2Ray 单独构建无需 Mihomo 或国内规则下载。链接更新不等于接管系统代理；OpenWrt 仅更新节点。

正式构建要求线路具备同批次、同配置的完整连接诊断和 30 分钟稳定性证据。候选仅用于隔离测试。发布、指定版本回滚、证书检查和清理见[部署指南](docs/deployment.md)。
