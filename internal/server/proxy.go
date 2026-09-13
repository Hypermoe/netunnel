package server

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"hypermoe/netunnel/internal/log"
	"hypermoe/netunnel/internal/netutil"
	"hypermoe/netunnel/internal/protocol"
	"hypermoe/netunnel/internal/stats"
)

// proxy 表示服务端上的一条公网端口映射。
//
// TCP 与 UDP 使用同一结构，二者共有映射元数据与统计信息，
// 差异体现在监听方式与转发路径上。
type proxy struct {
	name string
	spec protocol.ProxySpec
	// owner 指向拥有该映射的客户端，公网接入时需要其控制连接。
	owner *client
	srv   *Server

	logger    *log.Logger
	stats     stats.Proxy
	startedAt time.Time

	// ln 为 TCP 监听器，仅 TCP 映射非空。
	ln net.Listener
	// udpConn 为 UDP 监听套接字，仅 UDP 映射非空。
	udpConn *net.UDPConn

	// mu 保护 udpSessions。
	mu          sync.Mutex
	udpSessions map[string]*udpSession

	done      chan struct{}
	closeOnce sync.Once
}

// newProxy 构造端口映射对象，此时尚未开始监听。
func newProxy(s *Server, owner *client, spec protocol.ProxySpec) *proxy {
	return &proxy{
		name:        spec.Name,
		spec:        spec,
		owner:       owner,
		srv:         s,
		logger:      s.logger.WithPrefix(fmt.Sprintf("proxy:%s", spec.Name)),
		udpSessions: make(map[string]*udpSession),
		done:        make(chan struct{}),
	}
}

// start 占用公网端口并开始监听。
func (p *proxy) start() error {
	key := p.portKey()
	if err := p.srv.claimPort(key, p.name); err != nil {
		return fmt.Errorf("映射 %q 启动失败: %w", p.name, err)
	}
	if err := p.listen(); err != nil {
		// 监听失败必须归还端口占用，否则该端口在本进程内将永久不可用。
		p.srv.releasePort(key)
		return fmt.Errorf("映射 %q 启动失败: %w", p.name, err)
	}
	p.startedAt = time.Now()
	return nil
}

// listen 根据代理类型创建对应的监听并启动接收循环。
func (p *proxy) listen() error {
	addr := p.listenAddr()
	switch p.spec.Type {
	case protocol.ProxyTypeTCP:
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		p.ln = ln
		go p.acceptTCP()
		return nil

	case protocol.ProxyTypeUDP:
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		p.udpConn = conn
		go p.readUDP()
		go p.cleanUDP()
		return nil

	default:
		return fmt.Errorf("不支持的代理类型 %q", p.spec.Type)
	}
}

// close 停止端口映射并回收全部资源，可重复调用。
func (p *proxy) close() {
	p.closeOnce.Do(func() {
		close(p.done)
		if p.ln != nil {
			_ = p.ln.Close()
		}
		if p.udpConn != nil {
			_ = p.udpConn.Close()
		}
		p.closeUDPSessions()
		p.srv.releasePort(p.portKey())
		p.srv.unregisterProxy(p)
		p.logger.Infof("端口映射已关闭: %s %s -> %s", p.spec.Type, p.listenAddr(), p.spec.LocalAddr())
	})
}

// Closed 返回映射是否已关闭。
func (p *proxy) Closed() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// acceptTCP 接受公网 TCP 连接。
func (p *proxy) acceptTCP() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			select {
			case <-p.done:
				// 映射关闭导致的正常退出。
				return
			default:
			}
			p.logger.Warnf("接受公网连接失败: %v", err)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		go p.handleTCPConn(conn)
	}
}

// handleTCPConn 处理一条公网 TCP 连接。
//
// 流程：登记会话 -> 通知客户端 -> 等待工作连接接入 -> 双向转发。
func (p *proxy) handleTCPConn(conn net.Conn) {
	// 公网连接可能来自不可靠网络，开启保活以便及时感知对端断开。
	netutil.SetKeepAlive(conn)

	sessionID := protocol.MustSessionID()
	sess := p.srv.registerPending(sessionID)
	// 无论成功与否都要注销会话，防止 pending 表无界增长。
	defer p.srv.releasePending(sessionID, sess)
	defer func() { _ = conn.Close() }()

	notify := &protocol.Message{
		Type:       protocol.TypeNewProxy,
		ProxyName:  p.name,
		SessionID:  sessionID,
		Protocol:   protocol.ProxyTypeTCP,
		RemoteAddr: conn.RemoteAddr().String(),
	}
	if err := p.owner.send(notify); err != nil {
		p.logger.Warnf("通知客户端建立连接失败: %v", err)
		return
	}

	timeout := p.srv.cfg.WorkConnDuration()
	select {
	case workConn := <-sess.ch:
		p.stats.OpenConn()
		defer p.stats.CloseConn()
		p.logger.Debugf("连接已建立: %s <-> %s", conn.RemoteAddr(), workConn.RemoteAddr())
		// 公网 -> 隧道 计为入站流量，隧道 -> 公网 计为出站流量。
		netutil.Join(conn, workConn, p.stats.BytesIn(), p.stats.BytesOut())

	case <-time.After(timeout):
		p.logger.Warnf("等待客户端工作连接超时 (%s, 来源 %s)", timeout, conn.RemoteAddr())

	case <-p.done:
		p.logger.Debugf("映射已关闭，丢弃公网连接 %s", conn.RemoteAddr())
	}
}

// status 返回映射的运行状态快照。
func (p *proxy) status() ProxyStatus {
	snap := p.stats.Snapshot()
	status := "running"
	if p.Closed() {
		status = "stopped"
	}
	return ProxyStatus{
		Name:         p.name,
		Type:         p.spec.Type,
		RemoteAddr:   p.listenAddr(),
		LocalAddr:    p.spec.LocalAddr(),
		Status:       status,
		CurrentConns: snap.CurrentConns,
		TotalConns:   snap.TotalConns,
		BytesIn:      snap.BytesIn,
		BytesOut:     snap.BytesOut,
	}
}

// listenAddr 返回映射在服务端上的对外监听地址。
func (p *proxy) listenAddr() string {
	return net.JoinHostPort(p.srv.cfg.BindAddr, strconv.Itoa(p.spec.RemotePort))
}

// portKey 返回端口占用表的键。
// TCP 与 UDP 的端口空间相互独立，因此需要在键中带上协议类型。
func (p *proxy) portKey() string {
	return fmt.Sprintf("%s/%d", p.spec.Type, p.spec.RemotePort)
}

// addUDPSession 登记 UDP 会话。
func (p *proxy) addUDPSession(s *udpSession) {
	p.mu.Lock()
	p.udpSessions[s.key] = s
	p.mu.Unlock()
}

// removeUDPSession 移除 UDP 会话。
func (p *proxy) removeUDPSession(s *udpSession) {
	p.mu.Lock()
	if cur, ok := p.udpSessions[s.key]; ok && cur == s {
		delete(p.udpSessions, s.key)
	}
	p.mu.Unlock()
}

// closeUDPSessions 关闭全部 UDP 会话。
func (p *proxy) closeUDPSessions() {
	p.mu.Lock()
	sessions := make([]*udpSession, 0, len(p.udpSessions))
	for _, s := range p.udpSessions {
		sessions = append(sessions, s)
	}
	p.mu.Unlock()

	for _, s := range sessions {
		s.close()
	}
}

// udpSessionCount 返回当前 UDP 会话数量。
func (p *proxy) udpSessionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.udpSessions)
}
