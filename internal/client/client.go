// Package client 实现内网穿透客户端。
//
// 客户端主动向服务端建立一条控制连接并完成登录，随后：
//
//  1. 通过心跳维持控制连接，任意时刻断线后按指数退避自动重连；
//  2. 收到服务端的 TypeNewProxy 通知后，为本次公网访问建立一条
//     "工作连接"，并把服务端转发来的流量接入本地内网服务；
//  3. TCP 映射直接双向复制字节流，UDP 映射以定长帧在 TCP 隧道上
//     传输数据报，从而借助 TCP 的可靠性实现 UDP 数据的可靠投递。
package client

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"hypermoe/netunnel/internal/config"
	"hypermoe/netunnel/internal/log"
	"hypermoe/netunnel/internal/netutil"
	"hypermoe/netunnel/internal/protocol"
	"hypermoe/netunnel/internal/stats"
	"hypermoe/netunnel/internal/version"
)

// 重连退避参数。
const (
	// maxReconnectInterval 是退避等待的上限，避免长时间断线后等待过久。
	maxReconnectInterval = 30 * time.Second
	// stableRunDuration 表示连接稳定运行的时长阈值，超过后重置退避。
	stableRunDuration = time.Minute
)

// Client 是内网穿透客户端实例。
type Client struct {
	cfg    *config.ClientConfig
	logger *log.Logger

	// proxies 以映射名称索引本地映射规则，供处理工作连接时定位内网服务。
	proxies map[string]config.ProxyConfig
	// proxyStats 保存各映射的运行统计，供控制台状态展示。
	proxyStats map[string]*stats.Proxy

	startTime time.Time

	// mu 保护 conn、connectedAt、workConns 与 fatalErr。
	mu          sync.Mutex
	conn        net.Conn
	connectedAt time.Time
	// workConns 记录当前活跃的工作连接，断开控制连接时统一回收。
	workConns map[net.Conn]struct{}
	// fatalErr 记录导致客户端退出的致命错误，非空表示重连无法解决问题。
	fatalErr error

	done     chan struct{}
	doneOnce sync.Once
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New 创建客户端实例。
func New(cfg *config.ClientConfig, logger *log.Logger) *Client {
	c := &Client{
		cfg:        cfg,
		logger:     logger,
		proxies:    make(map[string]config.ProxyConfig, len(cfg.Proxies)),
		proxyStats: make(map[string]*stats.Proxy, len(cfg.Proxies)),
		workConns:  make(map[net.Conn]struct{}),
		done:       make(chan struct{}),
	}
	for _, p := range cfg.Proxies {
		c.proxies[p.Name] = p
		c.proxyStats[p.Name] = &stats.Proxy{}
	}
	return c
}

// Start 启动客户端：在后台运行连接与重连循环。
func (c *Client) Start() error {
	c.startTime = time.Now()

	c.wg.Add(1)
	go c.runLoop()
	return nil
}

// Stop 优雅停止客户端：关闭控制连接与所有工作连接，并退出重连循环。
// 可重复调用。
func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		c.closeDone()

		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		c.closeWorkConns()

		c.wg.Wait()
		c.logger.Infof("客户端已停止")
	})
}

// Done 返回在客户端停止时关闭的通道。
// 除主动停止外，遇到无法通过重连恢复的错误而退出时同样会关闭。
func (c *Client) Done() <-chan struct{} { return c.done }

// FatalErr 返回导致客户端退出的致命错误，正常停止时为 nil。
func (c *Client) FatalErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fatalErr
}

// closeDone 关闭停止信号，可重复调用。
func (c *Client) closeDone() {
	c.doneOnce.Do(func() { close(c.done) })
}

// exitOnFatal 记录致命错误、打印日志并关闭停止信号，终止重连循环。
func (c *Client) exitOnFatal(err error) {
	c.mu.Lock()
	c.fatalErr = err
	c.mu.Unlock()

	c.logger.Errorf("%v，进程退出", err)
	c.closeDone()
}

// runLoop 负责维持与服务端的连接，断线后按指数退避自动重连，直至被停止。
func (c *Client) runLoop() {
	defer c.wg.Done()

	backoff := c.cfg.ReconnectDuration()
	for {
		select {
		case <-c.done:
			return
		default:
		}

		start := time.Now()
		err := c.connectAndServe()
		if err != nil && !errors.Is(err, errStopped) {
			if errors.Is(err, errClientExists) {
				// 服务端已有同标识客户端在线，属于配置冲突，重连无法解决。
				c.exitOnFatal(err)
				return
			}
			if netutil.IsClosedError(err) {
				c.logger.Infof("与服务端连接已断开")
			} else {
				c.logger.Warnf("与服务端连接中断: %v", err)
			}
		}

		select {
		case <-c.done:
			return
		default:
		}

		// 稳定运行超过阈值说明连接质量良好，重置退避以缩短下次重连等待。
		if time.Since(start) >= stableRunDuration {
			backoff = c.cfg.ReconnectDuration()
		} else {
			backoff *= 2
			if backoff > maxReconnectInterval {
				backoff = maxReconnectInterval
			}
		}

		c.logger.Infof("%s 后尝试重连服务端", backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-c.done:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// errStopped 表示连接因客户端主动停止而结束，无需记录为异常。
var errStopped = errors.New("客户端已停止")

// errClientExists 表示服务端已存在同标识客户端在线。
// 这属于配置冲突而非临时故障，重连不会恢复，runLoop 遇到后直接退出。
var errClientExists = errors.New("客户端 ID 已被占用，请检查是否重复启动")

// connectAndServe 建立一次完整的控制连接：拨号、登录、心跳与报文收发。
// 返回错误表示本次连接结束，由 runLoop 决定何时重连。
func (c *Client) connectAndServe() error {
	addr := c.cfg.ServerAddrPort()
	dialer := net.Dialer{Timeout: c.cfg.DialDuration(), KeepAlive: 30 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("连接服务端 %s 失败: %w", addr, err)
	}
	// 保活需作用于原始 TCP 连接，须在后续包装之前设置。
	netutil.SetKeepAlive(conn)

	// 声明连接类型，服务端据此区分加密的控制连接与明文的工作连接。
	if err := protocol.WriteConnType(conn, protocol.ConnTypeControl); err != nil {
		_ = conn.Close()
		return fmt.Errorf("发送连接类型标记失败: %w", err)
	}

	// 配置了令牌时启用加密传输：令牌不再明文出现在线路上，改为两端
	// 共享的预共享密钥，服务端以"能否解密登录报文"完成认证。
	if c.cfg.Token != "" {
		secure, err := protocol.NewSecureConn(conn, c.cfg.Token)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("初始化加密连接失败: %w", err)
		}
		conn = secure
	}

	// 登录阶段使用握手超时，避免服务端无响应时长时间挂起。
	_ = conn.SetReadDeadline(time.Now().Add(c.cfg.DialDuration()))
	login := &protocol.Message{
		Type:     protocol.TypeLogin,
		ClientID: c.cfg.ClientID,
		Version:  version.Version,
		Proxies:  c.proxySpecs(),
	}
	if err := protocol.WriteMessage(conn, login); err != nil {
		_ = conn.Close()
		return fmt.Errorf("发送登录报文失败: %w", err)
	}

	resp, err := protocol.ReadMessage(conn)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("读取登录响应失败: %w", err)
	}
	if resp.Type != protocol.TypeLoginResp {
		_ = conn.Close()
		return fmt.Errorf("登录响应类型异常: %s", resp.Type)
	}
	if resp.Code != protocol.CodeOK {
		_ = conn.Close()
		if resp.Code == protocol.CodeClientExists {
			return fmt.Errorf("%w: %s", errClientExists, resp.Message)
		}
		return fmt.Errorf("登录被服务端拒绝 (code=%d): %s", resp.Code, resp.Message)
	}

	// 登录成功，清除读超时并改由心跳维持链路存活。
	_ = conn.SetReadDeadline(time.Time{})

	c.mu.Lock()
	c.conn = conn
	c.connectedAt = time.Now()
	c.mu.Unlock()
	c.logger.Infof("已连接服务端 %s，在线映射数=%d", addr, len(c.cfg.Proxies))

	// 控制连接断开后，残留的工作连接已无意义，需一并回收。
	defer func() {
		c.mu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		c.mu.Unlock()
		_ = conn.Close()
		c.closeWorkConns()
	}()

	hbDone := make(chan struct{})
	defer close(hbDone)
	go c.heartbeatLoop(conn, hbDone)

	return c.controlLoop(conn)
}

// heartbeatLoop 周期性地向服务端发送心跳，使服务端能够感知客户端存活。
func (c *Client) heartbeatLoop(conn net.Conn, done <-chan struct{}) {
	interval := c.cfg.HeartbeatDuration()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-done:
			return
		case <-ticker.C:
			msg := &protocol.Message{Type: protocol.TypeHeartbeat, Timestamp: time.Now().Unix()}
			if err := protocol.WriteMessage(conn, msg); err != nil {
				c.logger.Debugf("发送心跳失败: %v", err)
				return
			}
		}
	}
}

// controlReadTimeout 返回控制连接的读超时。
// 取值为心跳间隔的 3 倍，保证偶发丢包或调度延迟不会误判为断线。
func (c *Client) controlReadTimeout() time.Duration {
	timeout := 3 * c.cfg.HeartbeatDuration()
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	return timeout
}

// controlLoop 读取控制连接上的报文并分派处理，读到错误即结束本次连接。
func (c *Client) controlLoop(conn net.Conn) error {
	timeout := c.controlReadTimeout()
	for {
		select {
		case <-c.done:
			return errStopped
		default:
		}

		// 每收到一条报文即刷新读超时，超时说明服务端已失联。
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		msg, err := protocol.ReadMessage(conn)
		if err != nil {
			return err
		}

		switch msg.Type {
		case protocol.TypeHeartbeat:
			// 心跳仅用于刷新读超时。
		case protocol.TypeNewProxy:
			// 每条公网访问独立处理，避免建立工作连接的耗时阻塞控制连接读取。
			go c.handleNewProxy(msg)
		case protocol.TypeStop:
			return errors.New("收到服务端停止指令")
		default:
			c.logger.Debugf("忽略未知控制报文: %s", msg.Type)
		}
	}
}

// proxySpecs 把本地配置转换为登录报文所需的映射描述。
func (c *Client) proxySpecs() []protocol.ProxySpec {
	specs := make([]protocol.ProxySpec, 0, len(c.cfg.Proxies))
	for _, p := range c.cfg.Proxies {
		specs = append(specs, p.Spec())
	}
	return specs
}

// trackWorkConn 登记一条工作连接。
func (c *Client) trackWorkConn(conn net.Conn) {
	c.mu.Lock()
	c.workConns[conn] = struct{}{}
	c.mu.Unlock()
}

// untrackWorkConn 注销一条工作连接。
func (c *Client) untrackWorkConn(conn net.Conn) {
	c.mu.Lock()
	delete(c.workConns, conn)
	c.mu.Unlock()
}

// closeWorkConns 关闭全部活跃工作连接。
func (c *Client) closeWorkConns() {
	c.mu.Lock()
	conns := make([]net.Conn, 0, len(c.workConns))
	for conn := range c.workConns {
		conns = append(conns, conn)
	}
	c.workConns = make(map[net.Conn]struct{})
	c.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
}

// proxyStat 返回指定映射的统计计数器，不存在时返回 nil。
func (c *Client) proxyStat(name string) *stats.Proxy {
	return c.proxyStats[name]
}

// 状态查询 --------------------------------------------------------------------

// StatusSnapshot 是客户端运行状态快照，供前台控制台展示。
type StatusSnapshot struct {
	Role          string        `json:"role"`
	Version       string        `json:"version"`
	Server        string        `json:"server"`
	ClientID      string        `json:"client_id"`
	Connected     bool          `json:"connected"`
	ConnectedAt   string        `json:"connected_at,omitempty"`
	StartTime     string        `json:"start_time"`
	UptimeSeconds int64         `json:"uptime_seconds"`
	Proxies       []ProxyStatus `json:"proxies"`
}

// ProxyStatus 描述客户端上一条映射规则的运行情况。
type ProxyStatus struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	LocalAddr    string `json:"local_addr"`
	RemoteAddr   string `json:"remote_addr"`
	Status       string `json:"status"`
	CurrentConns int64  `json:"current_conns"`
	TotalConns   int64  `json:"total_conns"`
	BytesIn      int64  `json:"bytes_in"`
	BytesOut     int64  `json:"bytes_out"`
}

// Status 返回客户端当前状态快照。
func (c *Client) Status() StatusSnapshot {
	c.mu.Lock()
	connected := c.conn != nil
	connectedAt := c.connectedAt
	c.mu.Unlock()

	snap := StatusSnapshot{
		Role:          "client",
		Version:       version.Version,
		Server:        c.cfg.ServerAddrPort(),
		ClientID:      c.cfg.ClientID,
		Connected:     connected,
		StartTime:     c.startTime.Format(time.RFC3339),
		UptimeSeconds: stats.Uptime(c.startTime),
		Proxies:       make([]ProxyStatus, 0, len(c.cfg.Proxies)),
	}
	if connected && !connectedAt.IsZero() {
		snap.ConnectedAt = connectedAt.Format(time.RFC3339)
	}

	for _, p := range c.cfg.Proxies {
		st := c.proxyStats[p.Name]
		statSnap := stats.ProxySnapshot{}
		if st != nil {
			statSnap = st.Snapshot()
		}
		status := "offline"
		if connected {
			status = "running"
		}
		snap.Proxies = append(snap.Proxies, ProxyStatus{
			Name:         p.Name,
			Type:         p.Type,
			LocalAddr:    p.LocalAddr(),
			RemoteAddr:   net.JoinHostPort(c.cfg.ServerAddr, strconv.Itoa(p.RemotePort)),
			Status:       status,
			CurrentConns: statSnap.CurrentConns,
			TotalConns:   statSnap.TotalConns,
			BytesIn:      statSnap.BytesIn,
			BytesOut:     statSnap.BytesOut,
		})
	}
	return snap
}
