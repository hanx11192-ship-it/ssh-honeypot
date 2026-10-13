# sshhoney 🍯

**单文件、低依赖、稳定优先的 SSH 蜜罐** — 用 Go 编写，仅依赖 Go 标准库 + `golang.org/x/crypto/ssh` 官方协议栈。

> **为什么造这个轮子**：作者在生产环境使用 [jaksi/sshesame](https://github.com/jaksi/sshesame) 时，遇到两次「进程存活但停止 accept」的卡死（疑似与 tcpip_services 假端口转发相关），上游 v0.0.39（2024-08）后已停更无修复。于是自研了一个**在结构上不可能挂死**的替代品，日志格式与 sshesame 完全兼容，可以无缝替换。

📖 **[64 小时生产运行报告（REPORT.md）](REPORT.md)** — 288 个攻击源 IP 画像、两个恶意软件家族完整 TTP、稳定性对比与实战踩坑。

## 特性

| 特性 | 说明 |
|---|---|
| 🪶 **单文件零依赖** | ~400 行 Go，静态编译后仅 ~4MB，运行时 RSS ~8MB |
| 🛡️ **稳定性设计** | accept 循环永不退出；每连接/每会话 goroutine 顶层 `recover`；每连接硬寿命上限（默认 15 分钟），杜绝任何连接把资源占死 |
| 🕵️ **全量记录** | none 认证探测 / 密码 / 公钥 / exec 命令 / shell 交互输入 / 客户端版本 / pty 请求，全部落入 JSONL |
| 🎭 **隐身伪装** | 服务端版本串可自定义（默认伪装 `SSH-2.0-OpenSSH_9.7`），无 pre-auth banner 自曝 |
| 🖥️ **假命令输出** | `uname` / `whoami` / `hostname` / `id` / `uptime` / `cat /etc/os-release` 返回可定制的真实感指纹；支持 `;` `&&` `\|` 多命令拆分 |
| 💬 **伪交互 shell** | 假 prompt（`root@alpine:~# `），攻击者敲的每条命令逐字记录 |
| 🔌 **端口转发全拒** | 不提供假端口转发（这正是 sshesame 卡死的嫌疑面），`direct-tcpip` / `tcpip-forward` 一律拒绝并记录 |
| 📋 **日志兼容 sshesame** | 字段 `time` / `source` / `event_type` / `event` 完全对齐，现有轮转/看门狗/分析脚本零改动 |

## 实战数据

在生产 VPS 上运行 22 小时（放行前 3 次连接 + 第 4 次起 iptables DROP 的混合模式）：

- **零卡死、零重启**（对比 sshesame 上线 1 小时内卡死 2 次）
- 抓获 26 组真实弱口令、26 条登录后命令
- 捕获完整的 **mdrfckr 僵尸网络后门植入链**：`chattr -ia .ssh` → `rm -rf .ssh` → 植入 RSA-2048 后门公钥到 `authorized_keys`，7 个不同 IP 用逐字节一致的战术反复投递
- 黑名单自动积累 300+ 攻击源 IP

## 快速开始

### 1. 编译

```bash
# 任意装有 Go 1.21+ 的机器（可交叉编译）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sshhoney main.go
```

生成的二进制是**静态链接**的，可直接扔到任何 glibc/musl 的 Linux 上运行（Alpine 也可以）。

### 2. 生成主机密钥

```bash
mkdir -p /opt/sshhoney/keys
ssh-keygen -t ed25519 -f /opt/sshhoney/keys/host_ed25519_key -N ''
```

### 3. 创建运行用户并启动

```bash
useradd -r -s /sbin/nologin honeypot      # Debian/Ubuntu
# adduser -D -H -s /sbin/nologin honeypot # Alpine
chown -R honeypot:honeypot /opt/sshhoney
mkdir -p /var/log/sshhoney && chown honeypot:honeypot /var/log/sshhoney

# 绑定 1024 以下端口需要能力位（以非 root 运行）
setcap cap_net_bind_service=+ep /opt/sshhoney/sshhoney

# 前台试跑
sudo -u honeypot /opt/sshhoney/sshhoney -listen :22 -hostkey /opt/sshhoney/keys/host_ed25519_key
```

另开一个终端验证：

```bash
ssh -p 22 root@localhost   # 随便输入密码都能登录成功（这就是蜜罐）
uname -a                    # 返回伪造指纹
```

### 4. 安装为服务

**systemd**（Debian / Ubuntu / CentOS）：

```bash
cp deploy/sshhoney.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now sshhoney
```

**OpenRC**（Alpine / Gentoo）：

```bash
cp deploy/sshhoney-openrc /etc/init.d/sshhoney && chmod +x /etc/init.d/sshhoney
rc-update add sshhoney default && rc-service sshhoney start
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-listen` | `:22` | 监听地址 |
| `-hostkey` | （必填） | 主机私钥路径（ed25519 / rsa / ecdsa 均可） |
| `-log` | `/var/log/sshhoney/activity.jsonl` | JSONL 活动日志路径 |
| `-version` | `SSH-2.0-OpenSSH_9.7` | 伪装的服务端版本串 |
| `-max-life` | `15m` | 单连接最长寿命（挂死兜底） |
| `-uname` | Linux alpine 6.6.48… | 伪造的 `uname -a` 输出，**建议改成与你的伪装目标一致** |
| `-hostname` | `alpine` | 伪造主机名（shell prompt / hostname 命令） |

## 日志格式

与 [jaksi/sshesame](https://github.com/jaksi/sshesame) 完全兼容的 JSONL：

```json
{"time":"2026-10-09T21:42:03+08:00","source":"1.2.3.4:41928","event_type":"connection","event":{"client_version":"SSH-2.0-libssh_0.9.6"}}
{"time":"2026-10-09T21:42:03+08:00","source":"1.2.3.4:41928","event_type":"password_auth","event":{"user":"packer","accepted":true,"password":"packer"}}
{"time":"2026-10-09T21:42:04+08:00","source":"1.2.3.4:41928","event_type":"exec","event":{"channel_id":1,"command":"uname -a 2>/dev/null"}}
{"time":"2026-10-09T21:42:05+08:00","source":"1.2.3.4:41928","event_type":"shell_input","event":{"channel_id":2,"input":"whoami"}}
{"time":"2026-10-09T21:42:06+08:00","source":"1.2.3.4:41928","event_type":"publickey_auth","event":{"user":"root","accepted":true,"key_type":"ssh-rsa","fingerprint":"SHA256:..."}}
```

`event_type` 取值：`listening` / `connection` / `connection_close` / `no_auth` / `password_auth` / `publickey_auth` / `session` / `session_close` / `exec` / `shell` / `shell_input` / `pty` / `channel_rejected` / `handshake_failed` / `accept_error` / `panic_recovered`

快速看战果：

```bash
grep password_auth /var/log/sshhoney/activity.jsonl | tail -20   # 交出的账密
grep '"exec"' /var/log/sshhoney/activity.jsonl | tail -20        # 登录后命令
grep shell_input /var/log/sshhoney/activity.jsonl                # shell 交互输入
```

## 推荐部署架构：混合模式

单跑蜜罐只能收集到「先到先得」的几次尝试。更有效的玩法是 **蜜罐 + iptables 自动拉黑**（`deploy/iptables-hybrid.sh`）：

```
互联网 ──► 22 端口
            ├─ 每 IP 每 24h 前 3 次连接 ──► 喂给蜜罐（收集账密 + 登录后行为）
            └─ 第 4 次起 ──────────────► iptables DROP（xt_recent 记忆 24h）
互联网 ──► 233 端口 ──► 真实 sshd（你自己用）
```

```bash
# 扩大黑名单容量（内核默认只有 100 条，满后 FIFO 挤出）
echo "options xt_recent ip_list_tot=5000 ip_pkt_list_tot=50" > /etc/modprobe.d/xt_recent.conf

# 部署混合规则（前提：真实 sshd 已监听 10026 并测试可登录！）
./deploy/iptables-hybrid.sh 22 10026
```

配套运维脚本（见 `deploy/`）：

- **`honeypot-watchdog`** — 每 5 分钟探活 banner，蜜罐无响应自动重启并在 syslog 留证（fd 数量/上限）
- **`sshhoney-logrotate`** — 日志 >4MB 自动轮转，磁盘占用封顶（对小盘 VPS 友好）

## 设计细节：为什么它不会像 sshesame 一样挂死

1. **accept 循环永不退出** — `Accept()` 返回任何错误都只退避 1 秒重试，绝不 `break`/`return`
2. **每连接硬寿命** — `conn.SetDeadline(maxLife)`，即使某个对端故意不收数据，连接也会被内核回收
3. **panic 全recover** — 连接级和会话级两层 `recover()`，任何协议处理 bug 只记录 `panic_recovered` 事件，不拖垮进程
4. **主动关 channel** — exec/shell 处理完后服务端主动 `ch.Close()`（真实 sshd 行为）。不这样做会与「等服务端先关」的 OpenSSH 客户端形成死锁 —— 这正是开发期实测抓到的坑
5. **不提供假端口转发** — sshesame 的 `tcpip_services`（假 SMTP/HTTP/POP3）是其卡死的主要嫌疑面，sshhoney 从架构上砍掉了这块

## 已知限制

- 假命令输出只覆盖常见侦察命令（`uname`/`whoami`/`id`/`uptime`/`hostname`/`cat /etc/os-release`），其余命令返回空输出 + exit 0
- 伪 shell 是行缓冲实现，vim / top 等全屏交互程序行为不真实（对自动化 bot 场景足够）
- 不支持 SFTP/SCP（会以 channel 拒绝的形式记录）
- 单进程单端口；多端口伪装需多实例

## 免责声明

本项目仅用于**在自己拥有/授权的机器上**收集威胁情报与研究攻击者行为。请遵守当地法律法规，勿用于误导或陷害第三方。日志中会记录攻击者提交的明文密码，请妥善保管日志文件。

## License

MIT
