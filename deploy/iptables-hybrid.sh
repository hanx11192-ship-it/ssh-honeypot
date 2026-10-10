#!/bin/sh
# iptables 混合模式：真 SSH 端口保留，22 端口喂蜜罐并自动拉黑扫描者
#
# 语义：每个来源 IP 每 24 小时内，前 3 次连接 22 端口被放行（喂给蜜罐收集情报），
#       第 4 次起 DROP（xt_recent 24h 记忆）。黑名单容量由 xt_recent ip_list_tot 控制。
#
# 用法: ./iptables-hybrid.sh 22 10026
#   $1 = 蜜罐端口 (默认 22)
#   $2 = 真实 SSH 端口 (默认 10026，必须先让 sshd 监听它！)
#
# 注意：
#   1. 执行前确认真实 SSH 已监听 $2 且能用它登录，否则会把自己锁在外面
#   2. xt_recent 默认黑名单只有 100 条，建议扩容：
#      modprobe xt_recent ip_list_tot=5000 ip_pkt_list_tot=50
#      (持久化: /etc/modprobe.d/xt_recent.conf 写 options xt_recent ip_list_tot=5000 ip_pkt_list_tot=50)

HONEYPOT_PORT="${1:-22}"
REAL_SSH_PORT="${2:-10026}"

iptables -N SSH_GUARD 2>/dev/null
iptables -F SSH_GUARD

# 真实 SSH 端口放行
iptables -A SSH_GUARD -p tcp --dport "$REAL_SSH_PORT" -j ACCEPT
# 已建立的连接放行
iptables -A SSH_GUARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# 蜜罐端口前3次连接放行并记录
iptables -A SSH_GUARD -p tcp --dport "$HONEYPOT_PORT" --syn -m recent --set --name honeypot
# 第4次起 DROP（recent 时间窗 86400s = 24h）
iptables -A SSH_GUARD -p tcp --dport "$HONEYPOT_PORT" --syn -m recent --rcheck --seconds 86400 --hitcount 4 --name honeypot -j DROP

iptables -A INPUT -j SSH_GUARD

# 持久化 (Alpine): rc-service iptables save
echo "SSH_GUARD 链已部署: 22 前三连喂蜜罐, 第4连 DROP 24h; 真实 SSH 在 $REAL_SSH_PORT"
