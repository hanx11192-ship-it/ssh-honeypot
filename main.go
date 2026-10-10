// sshhoney — 单文件低依赖 SSH 蜜罐（自研，替代上游已停更且会卡死的 sshesame）
//
// 设计原则：
//   1. 稳定优先：accept 循环永不退出；每连接/每会话 goroutine 顶层 recover；
//      每连接硬寿命上限，杜绝任何连接把资源永久占死。
//   2. 全记录：no_auth 探测 / 密码 / 公钥 / exec 命令 / shell 输入 / 客户端版本。
//   3. 隐身：可自定义服务端版本串（伪装 OpenSSH），无 pre-auth banner。
//   4. 零依赖：仅 Go 标准库 + golang.org/x/crypto/ssh（官方协议栈）。
//   5. 日志 JSONL，字段与 sshesame 完全兼容（time/source/event_type/event），
//      现有轮转、看门狗、分析习惯零改动。
//
// 编译：CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o sshhoney main.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------- JSONL 日志 ----------

type jsonLogger struct {
	mu sync.Mutex
	f  *os.File
}

func openLogger(path string) (*jsonLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &jsonLogger{f: f}, nil
}

// write 任何情况下不 panic、不阻塞太久；写失败静默放弃（蜜罐不因日志盘满而死）。
func (l *jsonLogger) write(source, eventType string, event any) {
	if l == nil || l.f == nil {
		return
	}
	rec := struct {
		Time      string `json:"time"`
		Source    string `json:"source"`
		EventType string `json:"event_type"`
		Event     any    `json:"event"`
	}{
		Time:      time.Now().Format("2006-01-02T15:04:05-07:00"),
		Source:    source,
		EventType: eventType,
		Event:     event,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.mu.Lock()
	_, _ = l.f.Write(append(b, '\n'))
	l.mu.Unlock()
}

// ---------- 假命令输出 ----------

type fakeEnv struct {
	uname    string
	hostname string
	bootTime time.Time // 伪造的开机时刻，用于动态计算 uptime
}

func (fe fakeEnv) uptime() string {
	d := time.Since(fe.bootTime)
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf(" %s up %d days, %2d:%02d,  0 users,  load average: 0.01, 0.00, 0.00",
		time.Now().Format("15:04:05"), days, hours, mins)
}

// output 模拟常见侦察命令的 stdout；未识别的命令返回空（exit 0）。
// 支持 ; && || 分隔的多命令，逐段生成输出（更接近真实 shell 行为）。
func (fe fakeEnv) output(cmd string) string {
	var sb strings.Builder
	for _, part := range strings.FieldsFunc(cmd, func(r rune) bool {
		return r == ';' || r == '&' || r == '|'
	}) {
		if out := fe.outputSingle(part); out != "" {
			sb.WriteString(out)
			sb.WriteByte('\n')
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (fe fakeEnv) outputSingle(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	// 剥离常见重定向/管道修饰
	for _, s := range []string{"2>/dev/null", ">/dev/null", "2>&1"} {
		cmd = strings.ReplaceAll(cmd, s, "")
	}
	cmd = strings.TrimSpace(cmd)
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	switch fields[0] {
	case "uname":
		return fe.uname
	case "whoami":
		return "root"
	case "hostname":
		return fe.hostname
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)"
	case "uptime":
		return fe.uptime()
	case "cat":
		if len(fields) > 1 && strings.Contains(fields[len(fields)-1], "os-release") {
			return "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.2\nPRETTY_NAME=\"Alpine Linux v3.20\""
		}
		return ""
	default:
		return ""
	}
}

// ---------- 全局状态 ----------

var (
	listenAddr    = flag.String("listen", ":22", "监听地址")
	hostKeyPath   = flag.String("hostkey", "", "主机私钥路径 (ed25519/rsa/ecdsa)")
	logPath       = flag.String("log", "/var/log/sshhoney/activity.jsonl", "JSONL 日志路径")
	serverVersion = flag.String("version", "SSH-2.0-OpenSSH_9.7", "伪装的服务端版本串")
	maxLife       = flag.Duration("max-life", 15*time.Minute, "单连接最长寿命（防挂死兜底）")
	fakeUname     = flag.String("uname", "Linux alpine 6.6.48-0-virt #1-Alpine SMP PREEMPT_DYNAMIC 2024-08-30 06:20:46 x86_64 Linux", "伪造的 uname -a 输出")
	fakeHostname  = flag.String("hostname", "alpine", "伪造主机名")
)

var logger *jsonLogger

// ---------- SSH 服务端 ----------

func buildServerConfig(fe fakeEnv, signer ssh.Signer) *ssh.ServerConfig {
	config := &ssh.ServerConfig{
		ServerVersion: *serverVersion,
		MaxAuthTries:  6,
		// none 探测：记录后拒绝，迫使客户端交出真实字典密码
		NoClientAuthCallback: func(md ssh.ConnMetadata) (*ssh.Permissions, error) {
			logger.write(md.RemoteAddr().String(), "no_auth",
				map[string]any{"user": md.User(), "accepted": false})
			return nil, fmt.Errorf("no auth not allowed")
		},
		PasswordCallback: func(md ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			logger.write(md.RemoteAddr().String(), "password_auth",
				map[string]any{"user": md.User(), "accepted": true, "password": string(password)})
			return &ssh.Permissions{}, nil
		},
		PublicKeyCallback: func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			logger.write(md.RemoteAddr().String(), "publickey_auth",
				map[string]any{"user": md.User(), "accepted": true,
					"key_type": key.Type(), "fingerprint": ssh.FingerprintSHA256(key)})
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(signer)
	return config
}

func handleConn(nc net.Conn, config *ssh.ServerConfig, fe fakeEnv) {
	source := nc.RemoteAddr().String()
	defer func() {
		if r := recover(); r != nil {
			logger.write(source, "panic_recovered",
				map[string]any{"where": "conn", "error": fmt.Sprint(r)})
		}
		nc.Close()
		logger.write(source, "connection_close", map[string]any{})
	}()
	// 硬寿命上限：任何连接最多活 maxLife，杜绝挂死
	nc.SetDeadline(time.Now().Add(*maxLife))

	sconn, chans, reqs, err := ssh.NewServerConn(nc, config)
	if err != nil {
		// 认证前断开（TCP 探测、扫描器）属正常噪音
		logger.write(source, "handshake_failed", map[string]any{"error": err.Error()})
		return
	}
	logger.write(source, "connection",
		map[string]any{"client_version": string(sconn.ClientVersion())})
	// 全局请求（tcpip-forward 等）一律拒绝
	go ssh.DiscardRequests(reqs)

	cid := 0
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			// direct-tcpip 等一律拒绝（不提供假端口转发）
			newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			logger.write(source, "channel_rejected",
				map[string]any{"type": newCh.ChannelType()})
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		cid++
		id := cid
		logger.write(source, "session", map[string]any{"channel_id": id})
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.write(source, "panic_recovered",
						map[string]any{"where": "session", "error": fmt.Sprint(r)})
				}
			}()
			handleSession(ch, chReqs, id, source, fe)
		}()
	}
}

func handleSession(ch ssh.Channel, requests <-chan *ssh.Request, cid int, source string, fe fakeEnv) {
	defer func() {
		ch.Close()
		logger.write(source, "session_close", map[string]any{"channel_id": cid})
	}()
	for req := range requests {
		switch req.Type {
		case "exec":
			var m struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &m); err != nil {
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
			logger.write(source, "exec",
				map[string]any{"channel_id": cid, "command": m.Command})
			req.Reply(true, nil)
			if out := fe.output(m.Command); out != "" {
				io.WriteString(ch, out+"\n")
			}
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			// 服务端必须主动关闭 channel（真实 sshd 行为），
			// 否则与等待对端先关的 OpenSSH 客户端形成死锁
			ch.Close()
		case "shell":
			logger.write(source, "shell", map[string]any{"channel_id": cid})
			req.Reply(true, nil)
			fakeShell(ch, cid, source, fe)
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			ch.Close()
		case "pty-req":
			var m struct {
				Term     string
				Columns  uint32
				Rows     uint32
				Width    uint32
				Height   uint32
				Modelist string
			}
			if ssh.Unmarshal(req.Payload, &m) == nil {
				logger.write(source, "pty",
					map[string]any{"channel_id": cid, "term": m.Term})
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
		case "env":
			if req.WantReply {
				req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// fakeShell 伪交互 shell：假 prompt + 侦察命令假输出 + 全量输入记录。
// 已知限制：非行缓冲终端的特殊交互（vim 等）行为不真实，对 bot 场景足够。
func fakeShell(ch ssh.Channel, cid int, source string, fe fakeEnv) {
	prompt := "root@" + fe.hostname + ":~# "
	io.WriteString(ch, "Welcome to Alpine Linux 3.20 (kernel "+kernelShort(fe.uname)+")\n\n"+prompt)

	buf := make([]byte, 4096)
	var lineBuf []byte
	processLine := func(raw string) bool { // 返回 false 表示要退出 shell
		line := strings.TrimSpace(raw)
		line = strings.Trim(line, "\r\n")
		if line == "" {
			return true
		}
		logger.write(source, "shell_input", map[string]any{"channel_id": cid, "input": line})
		if line == "exit" || line == "logout" {
			return false
		}
		if out := fe.output(line); out != "" {
			io.WriteString(ch, out+"\n")
		}
		io.WriteString(ch, prompt)
		return true
	}

	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		lineBuf = append(lineBuf, buf[:n]...)
		for {
			idx := bytes.IndexAny(lineBuf, "\r\n")
			if idx < 0 {
				break
			}
			line := string(lineBuf[:idx])
			lineBuf = lineBuf[idx+1:]
			if !processLine(line) {
				return
			}
		}
		// 防御：极端长输入无换行，直接截断
		if len(lineBuf) > 65536 {
			lineBuf = nil
		}
	}
}

func kernelShort(uname string) string {
	fields := strings.Fields(uname)
	if len(fields) >= 3 {
		return fields[2]
	}
	return "6.6.48-0-virt"
}

// ---------- main：accept 永不退出 ----------

func main() {
	flag.Parse()
	var err error
	logger, err = openLogger(*logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open log:", err)
		os.Exit(1)
	}

	fe := fakeEnv{
		uname:    *fakeUname,
		hostname: *fakeHostname,
		bootTime: time.Now().Add(-26*24*time.Hour - 6*time.Hour),
	}

	keyData, err := os.ReadFile(*hostKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read hostkey:", err)
		os.Exit(1)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse hostkey:", err)
		os.Exit(1)
	}
	config := buildServerConfig(fe, signer)

	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(context.Background(), "tcp", *listenAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	logger.write("", "listening", map[string]any{"addr": *listenAddr, "version": *serverVersion})
	fmt.Printf("sshhoney listening on %s (banner: %s)\n", *listenAddr, *serverVersion)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// 任何 Accept 错误只退避重试，绝不退出循环
			logger.write("", "accept_error", map[string]any{"error": err.Error()})
			time.Sleep(time.Second)
			continue
		}
		go handleConn(conn, config, fe)
	}
}
