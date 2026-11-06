# 部署、升级和恢复

## 所有权与目录

`/opt/vrk/bin/<核心>/<版本>/` 保存校验后的官方二进制及收据；不同版本并存。`/var/lib/vrk/generations/` 保存候选和已部署配置，`current` 指向当前版本。秘密只允许 root 读取，运行配置由 root 写入、服务组 vrk 读取。

systemd 服务使用独立 vrk 用户，只有低端口绑定能力。文件名均以 `vrk-` 开头：Xray、每个 Hysteria 服务端/客户端、Realm，以及可选防火墙。服务名称或端口被其他软件占用时拒绝部署。

项目不会编辑旧的 xray.service、Docker 配置、网站、系统 DNS、默认路由、OpenWrt 或业务数据库。现有入口应在不同端口保持运行。

## 新 VPS 预检与上线顺序

以下检查在 VPS 上执行，首次部署前保留输出到仓库外。`dig`、`openssl`、`curl` 按需安装；基础运行依赖见 [README](../README.md#环境与准备)。

```sh
cat /etc/os-release
uname -m
python3 --version
systemd --version
ss -lntup
ip -4 route
ls -l /etc/resolv.conf
cat /etc/resolv.conf
systemctl is-active systemd-resolved unbound docker
```

最后一条中未安装的组件返回非零不表示整个环境失败。记录实际服务管理方式：systemd、Docker 或本项目单元，不以 `xray.service` 不存在判断 Docker Xray 已停机。虚拟机还需核对 CPU 指令集；出现 `Illegal instruction` 时先核对二进制构建和官方校验值，使用兼容构建，不先修改虚拟机 CPU 或升级生产核心。

按以下顺序逐台上线，每一步失败就停在当前主机：

1. 保留已有管理通道和入口，记录配置校验值、端口、服务启停及开机状态。SSH 指纹校验失败先核对身份，不关闭校验。
2. 验证系统和服务实际使用的 DNS、系统时间、CA 信任及 HTTPS 下载。检查 REALITY 目标 TLS 1.3 / XHTTP HTTP/2、Hysteria 域名证书及 ACME 条件。先排查 UDP DNS 丢回复或 DoT TCP 853 不通，不把换协议当成 DNS 修复。
3. 使用 `vrk backup` 保存项目资源；原有 Docker、解析器、网络管理器的配置由其所有者另行备份。备份取回后核对 SHA-256，见下文恢复边界。
4. 首次保留本机出口，在独立高端口部署单机入口；检查进程、实际代理 HTTPS、最终出口与双向传输。语法校验和 `active` 都不是连接验收。
5. 单机通过后再加 Realm 中转，先查中转机到落地机的对应 TCP/UDP，再查客户端完整路径。只换入口地址与端口，保留落地认证及证书身份。
6. 按[修复后的复验](testing.md#修复后的复验与退出条件)检查全部拟交付路径；通过后才导出正式节点。节点更新、订阅发布不重启 DNS、网络接口或原有代理服务。

## VPS DNS 部署与隔离

### 先确定谁在解析

至少区分：客户端 DNS、入口核心用于 REALITY 目标的系统解析、落地访问目标网站的解析、节点域名引导解析。修复其中一个不代表其他环节已经正常。锁定版本的 [Xray REALITY 实现](https://github.com/XTLS/Xray-core/blob/v26.5.9/transport/internet/reality/config.go)使用系统拨号器；仅设置 Xray 内置 `dns` 不能证明这条依赖已切换。

宿主机 `dig` 成功也不能替代容器或 systemd 挂载命名空间内检查。先选择最小影响范围：

| 运行方式 | 配置归属 | 应检查的位置 |
| --- | --- | --- |
| 项目自有 systemd 核心 | 私有部署 JSON 的 `service_dns` | 实际核心进程挂载命名空间的 `/etc/resolv.conf` |
| 既有 Docker 核心 | 原 Compose / 容器部署源的 DNS 字段 | `HostConfig.Dns`、容器内 resolver 与实际查询流量 |
| 整台 VPS 的本地解析器 | 原网络管理器、Unbound 与宿主机 resolver | 系统默认查询和服务内查询；影响所有使用系统 DNS 的应用 |

本项目只自动管理第一种。其他两种是人工运维方案，不是 `vrk apply` 的附加动作。

### 标准 Unbound 与 DoT

已验证可用的方案是发行版 Unbound → 带证书验证的 DoT 上游，保留 DNSSEC、正常缓存和 TTL，不靠过期答案隐藏解析故障。仅在公共 UDP DNS 确有丢包、错误或不可达证据时考虑迁移；现有解析正常无需统一替换。

先确认 TCP/UDP 53 未被占用、上游 TCP 853 可达、系统时间及 CA 正常。使用发行版软件包和标准服务，不修改启动脚本；以独立片段保存配置。以下是 Debian/Ubuntu 的回环示例，须检查现有 include、信任锚和重复配置，不能当作任意系统的整份配置覆盖：

```text
server:
    interface: 127.0.0.1
    access-control: 127.0.0.0/8 allow
    do-ip6: no
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
    cache-min-ttl: 0
    cache-max-ttl: 300
    prefetch: yes
    serve-expired: no
    log-queries: no
    log-replies: no
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-first: no
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
```

上游仅作格式示例，按当前 VPS 实测选择；需要冗余时增加经过验证的另一供应商。固定上游 IP 避免引导解析循环，`#服务名` 与 CA 包用于 TLS 身份校验；`forward-first: no` 防止转发失败改用递归解析。不要为修复 TLS 错误而去掉服务名、CA 或 DNSSEC 验证。配置语义见 [Unbound 官方手册](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#forward-zone-options)。

在确认端口无冲突并记录原服务状态后，可用 `apt-get install --no-install-recommends unbound dnsutils` 安装发行版组件；安装过程可能启动默认服务，不能把它当成不影响运行状态的下载操作。已有解析器时先审查，不重复安装或替换。

将片段保存为 `/etc/unbound/unbound.conf.d/vrk-dot.conf` 后，先校验，再在独立测试监听或维护窗口启动并检查；存在同名文件时比较归属，不覆盖：

```sh
unbound-checkconf
unbound-checkconf -o auto-trust-anchor-file
# 恢复步骤就绪后，启动尚未运行的解析器
systemctl enable --now unbound
# 已运行且属于本次维护范围时改用 systemctl reload unbound
dig @127.0.0.1 example.com A +time=2 +tries=1
dig @127.0.0.1 example.com AAAA +time=2 +tries=1
dig @127.0.0.1 example.com A +tcp +time=2 +tries=1
```

确认发行版已提供可读写权限正确的 DNSSEC 信任锚，使用其标准维护工具，不通过关闭验证来绕过失败。`unbound-control stats_noreset` 仅在该主机已配置 remote-control 时使用；控制接口未启用不等于 DNS 服务不可用。冷缓存与缓存命中分别测，记录 NOERROR / NXDOMAIN / SERVFAIL、回答和耗时；合法的 AAAA 空回答不是超时。非标准路径被 AppArmor 拒绝时先检查内核审计及发行版路径，不关闭 AppArmor。

Debian 软件包若启用了 resolvconf 辅助接管，另检查 `/etc/default/unbound` 中的 `RESOLVCONF` 与 `USE_RESOLVCONF_FORWARDS`。在需要独立维护上游、保持宿主机 DNS 原样的场景，将这两项设为 `false`，保留其他配置；先确认当前发行版 helper 确实读取这些选项。否则辅助程序可能修改宿主机 resolver，或从系统配置重新生成上游，破坏已声明的 DoT 路径。不要把这份 Debian 设置直接复制到采用其他管理方式的系统。

### 项目服务：通过 service_dns 接入

本地解析器验证通过后，在私有服务器 JSON 显式设置：

```json
{"service_dns":{"xray":["127.0.0.1"]}}
```

使用 `validate` → `backup` → `plan` → `apply`；完整字段见[配置说明](configuration.md#服务-dns)。只重启受影响的项目核心，同一 Xray 进程承载的入口会一起受影响。该设置不安装 Unbound，也不改变主机 DNS、其他容器、路由器或出口规则。

部署后用实际进程检查；以下只读命令在 VPS 上以 root 执行：

```sh
systemctl show vrk-xray -p MainPID -p InvocationID -p NRestarts
nsenter -t "$(systemctl show vrk-xray -p MainPID --value)" -m -- cat /etc/resolv.conf
cat /etc/resolv.conf
```

服务内应显示显式解析器，宿主机文件应与变更前校验值一致。出现 `226/NAMESPACE` 时检查源文件、权限、挂载命名空间支持与 unit 路径，不把它算作线路失败；候选未健康时由部署事务回滚。生成单元使用 [systemd BindReadOnlyPaths](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#BindPaths=)；路径含空格时仅分别引用源/目标路径，不把含分隔冒号的整串当成一个源路径。修复生成源后重新 `plan/apply`，不要手改生成 unit 或加启动后补丁。

### Docker 与宿主机已有服务

Docker 检查示例，`CONTAINER` 替换为目标容器名：

```sh
docker inspect -f '{{.HostConfig.NetworkMode}} {{json .HostConfig.Dns}}' CONTAINER
docker exec CONTAINER cat /etc/resolv.conf
```

桥接容器的 `127.0.0.1` 指向容器自身，不能直接使用宿主机回环解析器。需要宿主机 Unbound 时，先找实际网桥及容器网段，额外绑定该网桥地址，仅允许必要源网段，并从容器命名空间实际验证 UDP/TCP DNS。不要假设所有机器的网桥地址相同，不监听公网或允许全网递归。自定义网络可能显示 Docker 内置 DNS，须同时核对上游配置和真实流量，见 [Docker DNS 文档](https://docs.docker.com/engine/network/#dns-services)。

在原 Compose / 部署源声明容器 DNS，保存镜像摘要、端口、环境、挂载、网络、日志卷和重启策略后受控重建。只更改 DNS；保留可恢复的原容器，两个占用同一入口的容器不能同时启动。确认宿主机解析器及网桥启动依赖，节点更新和容器重建不能丢掉 DNS 声明。不要直接修改容器生成的 `/etc/resolv.conf`。

只有明确要让整台 VPS 使用本地解析器时才修改宿主机。先核对 `/etc/resolv.conf` 是普通文件还是符号链接，以及 cloud-init、systemd-resolved、NetworkManager、ifupdown、DHCP/resolvconf 谁拥有它；在实际所有者的原生配置中持久化，不能照搬另一台机器的 `/etc/network/interfaces` 或全局禁用网络管理。先让本地解析正常，再切换系统；不为 DNS 修改重启整个网络接口。验证 resolver 与受影响服务重启后的持久性；未做整机重启就注明未验证，不声称已覆盖。

## 配置更新

1. 编辑真实配置和私有节点凭据。
2. `vrk validate --config /private/server.json`。
3. `vrk plan --config /private/server.json --host root@host` 查看绑定、路由及防火墙需求。
4. `vrk apply --config /private/server.json --secrets /private/nodes.json --host root@host`。
5. 使用独立客户端验证实际出口和业务连接。

Xray 候选先以服务用户执行核心校验。Hysteria、Realm 没有项目依赖的稳定只解析接口，依靠本项目字段校验和激活后的进程/监听检查；不能声称这等同于完整业务验收。启动健康窗口最长 65 秒，首次 ACME 超时会回滚，不跳过 TLS 校验。

只对配置或二进制发生变化的服务进行重启。重复执行不旋转凭据，已停止的期望服务会恢复启动。配置切换仍可能中断这些入口的已有连接。

异常时恢复上一代配置、秘密、服务启停和开机启用状态。进程被强杀/主机断电可能留下 pending.json；下次 apply 会先恢复该事务。它不是独立自动恢复守护，也不等同于跨主机分布式事务。首次部署回滚恢复为没有本项目服务；已验证下载包和证书缓存保留。

## 备份与回滚

```sh
vrk backup --host root@host
vrk rollback --host root@host
# 指定服务器上的历史部署快照
vrk rollback --host root@host --snapshot /var/lib/vrk/backups/SNAPSHOT.json
```

归档包含配置、凭据、ACME 私钥与证书、部署历史；应通过 SCP 保存到受控位置，禁止上传公开附件。普通 rollback 使用同一服务器的部署快照，不解压任意归档。

卸载：`vrk uninstall --host root@host`，只停用和删除 manifest 中登记的服务。若单位文件被外部修改则拒绝卸载，避免误删。秘密、证书、二进制和备份默认保留，彻底销毁需自行审查这些目录后处理。

### 恢复范围与变更保护

`vrk backup` 不是整机备份：它不包含项目外 Unbound、Docker、网络管理器或原网站配置。人工 DNS 改造前另存相关文件（包括符号链接、权限、属主）、容器元数据、原服务启用/运行状态和 SHA-256；在独立管理通道可用、恢复步骤可执行后才切换。

独立于 SSH 的十分钟回滚保护、跨重启固定时刻计时器并非 `vrk apply` 内置功能。涉及宿主机或容器 DNS 时，应另用原生 systemd service/timer 准备只恢复本批文件与服务状态的受控恢复操作，核对待恢复配置仍属于本批；管理连接、解析与真实代理检查通过后解除并清理临时单元。不能用只在 SSH 中运行的 sleep 充当保护，也不能在仍持有同一变更锁时同步调用回滚等待自己释放锁。

项目变更优先绑定 `apply` 返回的 `previous_backup` 与 `generation`，不要在已发生其他部署后盲目恢复“上一版”：

```sh
vrk rollback --host root@host \
  --snapshot /var/lib/vrk/backups/SNAPSHOT.json \
  --expected-generation GENERATION_FROM_THIS_APPLY
```

发现 generation 或外部文件校验值变化时先比较现场，禁止覆盖后续工作。部署快照恢复与项目外 DNS 恢复是两个操作，前者不会撤销手工安装的解析器。恢复时先保证旧 DNS 路径可用，再停用本批新增解析器；不恢复整机、数据库或无关代理服务。分别记录“恢复前置条件检查”“真实回滚演练”“服务重启”“宿主机重启”，不能互相替代。

## 升级

版本锁位于 `vrk/versions.lock.json`。先审查官方 release，填入明确版本、架构包 URL 和 SHA-256，运行核心兼容测试，再执行：

```sh
vrk upgrade --config /private/server.json --component xray --to REVIEWED_VERSION --host root@host
```

升级使用整份已审查锁文件；有多个核心版本变化时会一起形成一个部署批次，`--component/--to` 是显式目标核对，不是忽略其他锁文件差异。核心永不跟随 latest 自动更新。TLS 或哈希校验失败会停止；不会执行下载下来的安装脚本。

## 防火墙与端口

默认只在 plan 中列出需要放行的端口，不修改防火墙。入口使用的 TCP/UDP 端口和 ACME TCP 80 必须在系统及云厂商安全组放行。

可在配置顶层显式设置 `"manage_firewall": true` 使用独立 `inet vrk` 表和原生 oneshot 服务。仅添加本项目所需放行，不修改其他表；有既存 drop/reject 终止策略时拒绝自动协调，改由原防火墙管理器添加端口。此功能不能替代云安全组，也不是给既有宽松防火墙增加完整安全基线。

## 首次证书

先在 DNS 提供商创建正确的仅 DNS A 记录。项目不保存 DNS 账户或 API Token。HTTP-01 无法在被占用的 80 端口旁自动工作；请选择现有证书文件，不自动重写 Nginx。

证书由 Hysteria 内置 ACME 自动维护。验证日志中的签发/维护状态和实际 TLS；不要调整系统时间模拟未来续期。自有静态 HTTP/3 页面与 REALITY 的 TCP 监听可以同时存在，但不代表 TCP/UDP 网站表现完全相同。

## 静态订阅发布

参考 [发布配置](../examples/subscription-publish.json)。在 Web 主机提供标准 Nginx、openssl、systemd、runuser、curl 及可读取的有效证书。指定独立 root、domain、base_url、listen、port、certificate、key、worker user（默认 www-data）和 nginx 二进制。base_url 为客户端访问的 HTTPS 地址，域名须匹配证书；默认端口与监听一致，显式反向代理场景见下文。证书由既有流程维护，续期后须重载对应静态 Nginx 单元以加载新证书；不为发布器改动网站、443 或 ACME 80。

`subscription publish` 可本机 root 执行，也可通过 `--host/--jump` 将构建和私有访问文件临时上传。只维护专用发布目录和按目录派生名称的 vrk-subscription-*.service。已有目录无所有权记录、端口占用、证书无效、文件哈希错误、空订阅或外部修改服务单元时停止。候选配置通过 nginx -t 后切换发布内容，随后通过严格 TLS 的本机 HTTPS 检查核对文件哈希，再提交状态；代理服务不重启。

访问文件首次生成随机令牌，保存在仓库外。链接路径为 `/令牌/nodes.json`、`/令牌/desktop.json`、`/令牌/v2ray.txt`。关闭目录列表、访问日志和共享缓存；原始配置与私钥不放进托管目录。令牌只控制订阅获取，不撤销已经下载的代理账号。

```sh
vrk subscription token --access-file /private/access.json --rotate
# 发布后才启用新令牌并撤销旧令牌
vrk subscription publish --bundle /private/release-2 --publish-config /private/publish.json \
  --access-file /private/access.json --host root@web-host
vrk subscription rollback --publish-config /private/publish.json \
  --access-file /private/access.json --host root@web-host
```

回滚恢复上一份产物，但保留当前访问令牌，避免重新启用已撤销链接。首次导入需要访问源站；已加载节点和规则不依赖订阅服务器持续在线。既有缓存不是首次无缓存时的可用保证。

发布时国内规则是冻结版本，随同订阅静态托管。规则更新须重新下载校验、构建和发布；客户端更新失败保留上一份有效缓存。没有后台网络策略生成器或规则更新脚本。

## 部署影响与真实连接验收

`plan` 的 service_impact 列出新增、移除、预计重启及受影响监听；共享 Xray 的入口合并展示。预览不生成密钥，导入凭据变化仍须应用时核对。

`apply/upgrade` 可选 `--verify-cases /private/cases.json --verify-output /private/new-acceptance-dir`。SSH 时从管理机运行前后检查；本机时在执行主机检查。清单至少两个明确 HTTPS 目标，部署验收建议 rounds=1、interval=0；长期观察独立使用 verify。输出保存 before/after、decision，以及发生回滚时的 restored。

单站失败或部署前已有异常不直接触发回滚；至少两个此前正常目标同时退化才恢复本批。重复 apply 未改变配置时不因外部失败回滚旧批次。结果无法确定时保留现场、返回非零；SSH 结果未知时不得自动重复部署。该机制不能仅靠 HTTP 状态精确归因，仍需分段证据。

## 固定公开入口与恢复

公开构建使用 `--access-mode public --name builder`；发布不需要访问文件。访问模式和固定路径记录在产物清单中，不能通过改文件名绕过验收。反向代理场景在发布配置显式设置 `reverse_proxy: true`，允许 `base_url` 的公开端口与源站 `port` 不同；域名仍须匹配证书。私有 CA 使用 `ca_file` 指定信任链，禁止关闭证书校验。

Cloudflare 示例：仅为订阅主机名设置代理 DNS、回源 8443、严格证书校验和缓存绕过；不修改全域其他网站的规则。源站采用发行版 Nginx、logrotate 和独立 systemd 单元，不启用默认站点。Origin CA 只用于代理回源，关闭 Cloudflare 代理后不保证普通浏览器信任该证书。

重复发布当前版本保留原上一版。使用 `subscription rollback --revision <20位版本> --publish-config ...` 指定版本；不指定则恢复上一版。恢复保持当前访问令牌。发布失败恢复目录、配置及服务运行状态；pending.json 未完成事务会在下一次发布时先恢复。SSH 未知结果应先检查，不重复发布来猜测结果。

`subscription status --publish-config ...` 显示版本、进程、待恢复事务及证书是否在 90 天内到期。错误日志为私有文件，通过项目在 `/etc/logrotate.d` 的独立条目按 5 MB、7 份轮转；不记录访问日志。证书更新后重新发布当前版本，完成校验、重载和 HTTPS 检查。

`subscription prune --publish-config ...` 默认只预览，`--execute` 才删除；默认最近 5 版及最近 30 天保留，当前、上一版和未完成事务保护。证书、凭据和备份不删除。远端发布／回滚／检查／清理支持 `--host` 和 `--jump`。

部署连接验收的自动回滚使用该次快照，并在锁内核对 generation；其他部署已修改当前版本时拒绝回滚，保留冲突证据。
