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
