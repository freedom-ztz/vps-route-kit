# 部署、升级和恢复

## 所有权与目录

`/opt/vrk/bin/<核心>/<版本>/` 保存校验后的官方二进制及收据；不同版本并存。`/var/lib/vrk/generations/` 保存候选和已部署配置，`current` 指向当前版本。秘密只允许 root 读取，运行配置由 root 写入、服务组 vrk 读取。

systemd 服务使用独立 vrk 用户，只有低端口绑定能力。文件名均以 `vrk-` 开头：Xray、每个 Hysteria 服务端/客户端、Realm，以及可选防火墙。服务名称或端口被其他软件占用时拒绝部署。

项目不会编辑旧的 xray.service、Docker 配置、网站、系统 DNS、默认路由、OpenWrt 或业务数据库。现有入口应在不同端口保持运行。

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

参考 [发布配置](../examples/subscription-publish.json)。在 Web 主机提供标准 Nginx、openssl、systemd、runuser、curl 及可读取的有效证书。指定独立 root、domain、base_url、listen、port、certificate、key、worker user（默认 www-data）和 nginx 二进制。base_url 为 HTTPS 源站，域名和端口必须与监听一致。证书由既有流程维护，续期后须重载对应静态 Nginx 单元以加载新证书；不为发布器改动网站、443 或 ACME 80。

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
