package server

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"netunnel/internal/log"
	"netunnel/internal/netutil"
	"netunnel/internal/protocol"
)

// client 表示一个已登录的客户端控制连接。
type client struct {
	id          string
	remoteAddr  string
	connectedAt time.Time

	srv    *Server
	logger *log.Logger
	conn   net.Conn
	// sendCh 缓冲待发送的控制报文，保证控制连接的写入始终由单一协程完成。
	sendCh    chan *protocol.Message
	done      chan struct{}
	closeOnce sync.Once

	mu      sync.RWMutex
	proxies []*proxy
}

// pending 表示一次等待工作连接接入的会话。
type pending struct {
	ch chan net.Conn
	// closed 标记会话已被注销，避免重复投递。
	closed bool
}

// handleConn 处理控制端口上的一条新连接。
//
// 通过首条报文区分连接类型：登录报文建立控制连接，工作连接报文
// 则与之前登记的公网会话配对。
func (s *Server) handleConn(conn net.Conn) {
	netutil.SetKeepAlive(conn)
	// 防止恶意或异常客户端占用连接而不发送任何报文。
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.HandshakeDuration()))

	msg, err := protocol.ReadMessage(conn)
	if err != nil {
		s.logger.Debugf("读取握手报文失败 (来源 %s): %v", conn.RemoteAddr(), err)
		_ = conn.Close()
		return
	}

	switch msg.Type {
	case protocol.TypeLogin:
		s.handleLogin(conn, msg)
	case protocol.TypeNewWorkConn:
		s.handleWorkConn(conn, msg)
	default:
		s.logger.Warnf("收到未知类型的握手报文 %q (来源 %s)", msg.Type, conn.RemoteAddr())
		_ = conn.Close()
	}
}

// handleLogin 处理客户端登录。
func (s *Server) handleLogin(conn net.Conn, msg *protocol.Message) {
	remote := conn.RemoteAddr().String()

	// 使用恒定时间比较，避免通过响应时间推断令牌。
	if subtle.ConstantTimeCompare([]byte(msg.Token), []byte(s.cfg.Token)) != 1 {
		s.logger.Warnf("客户端 %s 令牌校验失败", remote)
		s.replyLoginError(conn, protocol.CodeAuthFailed, "令牌校验失败")
		return
	}

	clientID := strings.TrimSpace(msg.ClientID)
	if clientID == "" {
		// 未声明标识时退化为来源地址，保证注册表键唯一可用。
		clientID = remote
	}

	c := &client{
		id:          clientID,
		remoteAddr:  remote,
		connectedAt: time.Now(),
		srv:         s,
		// 复用服务端日志输出目标，仅替换前缀，便于区分来源。
		logger: s.logger.WithPrefix(fmt.Sprintf("client:%s", clientID)),
		conn:   conn,
		sendCh: make(chan *protocol.Message, 64),
		done:   make(chan struct{}),
	}

	if err := s.registerClient(c); err != nil {
		s.logger.Warnf("客户端 %s 注册失败: %v", remote, err)
		code := protocol.CodeInternalError
		if strings.Contains(err.Error(), "已在线") {
			code = protocol.CodeClientExists
		}
		s.replyLoginError(conn, code, err.Error())
		return
	}

	if err := s.setupProxies(c, msg.Proxies); err != nil {
		s.logger.Warnf("客户端 %s 建立端口映射失败: %v", remote, err)
		s.replyLoginError(conn, protocol.CodeProxyError, err.Error())
		s.unregisterClient(c)
		return
	}

	// 握手完成，清除读超时，改由心跳机制维持连接。
	_ = conn.SetReadDeadline(time.Time{})
	resp := &protocol.Message{
		Type:     protocol.TypeLoginResp,
		Code:     protocol.CodeOK,
		Message:  "ok",
		ClientID: clientID,
	}
	if err := protocol.WriteMessage(conn, resp); err != nil {
		s.logger.Warnf("回复客户端 %s 登录结果失败: %v", remote, err)
		s.unregisterClient(c)
		_ = conn.Close()
		return
	}

	s.logger.Infof("客户端已上线: 标识=%s 地址=%s 映射数=%d 版本=%s",
		clientID, remote, len(c.proxies), msg.Version)

	go c.writeLoop()
	c.readLoop()
}

// replyLoginError 向客户端回复登录失败原因并关闭连接。
func (s *Server) replyLoginError(conn net.Conn, code int, message string) {
	resp := &protocol.Message{Type: protocol.TypeLoginResp, Code: code, Message: message}
	if err := protocol.WriteMessage(conn, resp); err != nil {
		s.logger.Debugf("回复登录失败信息出错: %v", err)
	}
	_ = conn.Close()
}

// handleWorkConn 处理客户端建立的工作连接，并将其与等待中的公网会话配对。
func (s *Server) handleWorkConn(conn net.Conn, msg *protocol.Message) {
	// 工作连接不参与控制报文交互，进入数据转发阶段后由会话自行管理超时，
	// 因此需清除握手阶段的读超时，否则空闲超过握手超时会被误判为超时并中断转发。
	_ = conn.SetReadDeadline(time.Time{})

	if !s.deliverWorkConn(msg.SessionID, conn) {
		s.logger.Warnf("工作连接 %s 未匹配到会话 (可能已超时)", msg.SessionID)
		resp := &protocol.Message{
			Type:    protocol.TypeNewWorkConnResp,
			Code:    protocol.CodeSessionNotFound,
			Message: "会话不存在或已超时",
		}
		_ = protocol.WriteMessage(conn, resp)
		_ = conn.Close()
		return
	}

	// 通知客户端配对成功，之后连接进入数据转发阶段。
	resp := &protocol.Message{Type: protocol.TypeNewWorkConnResp, Code: protocol.CodeOK, Message: "ok"}
	if err := protocol.WriteMessage(conn, resp); err != nil {
		s.logger.Debugf("回复工作连接握手结果失败: %v", err)
		_ = conn.Close()
	}
}

// registerPending 登记一次待配对的公网会话。
func (s *Server) registerPending(sessionID string) *pending {
	p := &pending{ch: make(chan net.Conn, 1)}
	s.mu.Lock()
	s.pending[sessionID] = p
	s.mu.Unlock()
	return p
}

// releasePending 注销会话，并回收可能已投递但无人接收的工作连接。
//
// deliverWorkConn 与该方法都持有 s.mu 完成"查找 + 投递/注销"，因此不会
// 出现连接被投入通道后无人处理的泄漏窗口。
func (s *Server) releasePending(sessionID string, p *pending) {
	s.mu.Lock()
	if cur, ok := s.pending[sessionID]; ok && cur == p {
		delete(s.pending, sessionID)
		p.closed = true
	}
	s.mu.Unlock()

	select {
	case wc := <-p.ch:
		_ = wc.Close()
	default:
	}
}

// deliverWorkConn 把工作连接投递给等待中的会话，返回 false 表示会话不存在。
func (s *Server) deliverWorkConn(sessionID string, conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.pending[sessionID]
	if !ok || p.closed {
		return false
	}
	delete(s.pending, sessionID)
	// 通道容量为 1 且每个会话只会投递一次，此处不会阻塞。
	p.ch <- conn
	return true
}

// setupProxies 为客户端创建全部端口映射。
//
// 采用"先全部校验、再逐个启动、失败即回滚"的策略，避免部分映射生效
// 造成客户端状态与预期不一致。
func (s *Server) setupProxies(c *client, specs []protocol.ProxySpec) error {
	if len(specs) == 0 {
		return errors.New("客户端未声明任何端口映射规则")
	}

	names := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		if err := protocol.ValidateProxySpec(spec); err != nil {
			return err
		}
		if _, dup := names[spec.Name]; dup {
			return fmt.Errorf("映射名称 %q 重复", spec.Name)
		}
		names[spec.Name] = struct{}{}

		if spec.RemotePort == s.cfg.BindPort {
			return fmt.Errorf("映射 %q 的公网端口 %d 与服务端控制端口冲突", spec.Name, spec.RemotePort)
		}
	}

	created := make([]*proxy, 0, len(specs))
	for _, spec := range specs {
		p := newProxy(s, c, spec)
		if err := p.start(); err != nil {
			// 回滚已启动的映射，保证登录失败后服务端不留残余监听。
			for _, done := range created {
				done.close()
			}
			return err
		}
		created = append(created, p)
	}

	for _, p := range created {
		c.addProxy(p)
		s.registerProxy(p)
		s.logger.Infof("端口映射已生效: %s %s:%d -> %s (客户端 %s)",
			p.spec.Type, s.cfg.BindAddr, p.spec.RemotePort, p.spec.LocalAddr(), c.id)
	}
	return nil
}

// addProxy 把映射挂到客户端上，供断线时统一回收。
func (c *client) addProxy(p *proxy) {
	c.mu.Lock()
	c.proxies = append(c.proxies, p)
	c.mu.Unlock()
}

// proxyList 返回客户端持有的映射副本。
func (c *client) proxyList() []*proxy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*proxy, len(c.proxies))
	copy(out, c.proxies)
	return out
}

// send 将控制报文投递到发送队列。
// 队列满或等待超时即认为客户端异常，避免阻塞公网接入流程。
func (c *client) send(msg *protocol.Message) error {
	select {
	case c.sendCh <- msg:
		return nil
	case <-c.done:
		return errors.New("客户端连接已关闭")
	case <-time.After(sendTimeout):
		return errors.New("发送控制报文超时")
	}
}

// writeLoop 是控制连接唯一的写入方，串行发送控制报文与心跳。
func (c *client) writeLoop() {
	// 服务端主动发送心跳，使客户端也能及时发现链路异常。
	interval := c.srv.cfg.HeartbeatTimeoutDuration() / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case msg := <-c.sendCh:
			if err := protocol.WriteMessage(c.conn, msg); err != nil {
				c.logger.Debugf("发送控制报文失败: %v", err)
				c.close()
				return
			}
		case <-ticker.C:
			hb := &protocol.Message{Type: protocol.TypeHeartbeat, Timestamp: time.Now().Unix()}
			if err := protocol.WriteMessage(c.conn, hb); err != nil {
				c.logger.Debugf("发送心跳失败: %v", err)
				c.close()
				return
			}
		}
	}
}

// readLoop 读取控制连接上的报文，并在超时或出错时清理客户端。
func (c *client) readLoop() {
	defer c.close()

	timeout := c.srv.cfg.HeartbeatTimeoutDuration()
	for {
		// 每收到一条报文即刷新读超时；客户端心跳间隔应小于该值。
		_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
		msg, err := protocol.ReadMessage(c.conn)
		if err != nil {
			if !netutil.IsClosedError(err) {
				c.logger.Warnf("控制连接读取失败: %v", err)
			}
			return
		}

		switch msg.Type {
		case protocol.TypeHeartbeat:
			// 心跳仅用于刷新读超时，无需额外处理。
		case protocol.TypeStop:
			c.logger.Warnf("收到服务端停止指令，主动断开")
			return
		default:
			c.logger.Debugf("忽略未知控制报文: %s", msg.Type)
		}
	}
}

// close 关闭客户端控制连接并回收其端口映射，可重复调用。
func (c *client) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.conn.Close()
		c.closeProxies()
		c.srv.unregisterClient(c)
		c.logger.Infof("客户端已离线: 标识=%s 地址=%s", c.id, c.remoteAddr)
	})
}

// closeProxies 关闭该客户端的全部端口映射。
func (c *client) closeProxies() {
	for _, p := range c.proxyList() {
		p.close()
	}
}

// status 返回客户端的运行状态快照。
func (c *client) status() ClientStatus {
	cs := ClientStatus{
		ClientID:     c.id,
		RemoteAddr:   c.remoteAddr,
		ConnectedAt:  c.connectedAt.Format(time.RFC3339),
		UptimeSecond: int64(time.Since(c.connectedAt).Seconds()),
	}
	for _, p := range c.proxyList() {
		cs.Proxies = append(cs.Proxies, p.status())
	}
	return cs
}
