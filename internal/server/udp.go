package server

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"netunnel/internal/log"
	"netunnel/internal/netutil"
	"netunnel/internal/protocol"
)

// udpEnqueueTimeout 是向会话出站队列投递数据报的最长等待时间。
// 短暂等待可吸收突发流量，超时则丢弃，避免单个来源拖垮接收循环。
const udpEnqueueTimeout = 2 * time.Second

// udpQueueSize 是单会话出站队列长度。
// 队列用于在隧道尚未就绪或瞬时拥塞时暂存数据报，容量按突发流量经验值设定。
const udpQueueSize = 256

// udpSession 表示服务端上一条"公网来源 <-> 内网服务"的 UDP 会话。
//
// 每条会话独占一条到客户端的 TCP 工作连接，UDP 数据报以定长帧
// （protocol.WriteFrame / ReadFrame）在该连接上传输，从而借助 TCP 的
// 可靠、有序、去重特性实现 UDP 数据的可靠投递，同时保留数据报边界。
type udpSession struct {
	// key 为公网来源地址（IP:端口），用作会话在映射内的唯一标识。
	key string
	// addr 为公网访问方地址，回写应答时使用。
	addr *net.UDPAddr
	// proxy 指向所属的端口映射。
	proxy *proxy
	// logger 为带代理前缀的日志器。
	logger *log.Logger

	// sendCh 暂存待写入隧道的数据报，由 writeTunnel 协程消费。
	sendCh chan []byte
	// lastActive 记录最近活跃时间（Unix 纳秒），用于空闲回收。
	lastActive atomic.Int64

	// mu 保护 conn，避免建立协程与关闭流程并发读写。
	mu   sync.Mutex
	conn net.Conn

	done      chan struct{}
	closeOnce sync.Once
}

// newUDPSession 构造 UDP 会话，此时隧道尚未建立。
func newUDPSession(p *proxy, key string, addr *net.UDPAddr) *udpSession {
	s := &udpSession{
		key:    key,
		addr:   addr,
		proxy:  p,
		logger: p.logger,
		sendCh: make(chan []byte, udpQueueSize),
		done:   make(chan struct{}),
	}
	s.touch()
	return s
}

// touch 刷新会话的活跃时间。
func (s *udpSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

// lastActiveAt 返回会话最近一次活跃时间。
func (s *udpSession) lastActiveAt() time.Time {
	return time.Unix(0, s.lastActive.Load())
}

// enqueue 把一个来自公网的数据报放入出站队列。
// payload 会在内部复制，调用方可安全复用其缓冲区。
func (s *udpSession) enqueue(payload []byte) {
	buf := make([]byte, len(payload))
	copy(buf, payload)

	timer := time.NewTimer(udpEnqueueTimeout)
	defer timer.Stop()
	select {
	case s.sendCh <- buf:
	case <-s.done:
		// 会话已关闭，数据报随会话一并丢弃。
	case <-timer.C:
		s.logger.Warnf("UDP 会话出站队列已满，丢弃数据报 (来源 %s)", s.key)
	}
}

// run 建立隧道并驱动该会话的双向转发，直到会话结束。
func (s *udpSession) run() {
	workConn, err := s.dialTunnel()
	if err != nil {
		s.logger.Warnf("UDP 会话隧道建立失败 (来源 %s): %v", s.key, err)
		s.close()
		return
	}
	if !s.attach(workConn) {
		// 会话在建立期间已被关闭，attach 内部已完成清理。
		return
	}
	s.logger.Debugf("UDP 隧道已建立: %s", s.key)

	// 隧道 -> 公网方向的读取协程：退出即关闭整个会话。
	go s.readTunnel()
	// 当前协程负责 公网 -> 隧道 方向，直至会话结束。
	s.writeTunnel()
}

// dialTunnel 请求客户端为该 UDP 会话建立一条工作连接。
func (s *udpSession) dialTunnel() (net.Conn, error) {
	srv := s.proxy.srv
	sessionID := protocol.MustSessionID()

	pend := srv.registerPending(sessionID)
	// 无论成功与否都要注销会话，防止 pending 表无界增长。
	defer srv.releasePending(sessionID, pend)

	notify := &protocol.Message{
		Type:       protocol.TypeNewProxy,
		ProxyName:  s.proxy.name,
		SessionID:  sessionID,
		Protocol:   protocol.ProxyTypeUDP,
		RemoteAddr: s.key,
	}
	if err := s.proxy.owner.send(notify); err != nil {
		return nil, fmt.Errorf("通知客户端建立工作连接失败: %w", err)
	}

	timeout := srv.cfg.WorkConnDuration()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case workConn := <-pend.ch:
		return workConn, nil
	case <-timer.C:
		return nil, fmt.Errorf("等待客户端工作连接超时 (%s)", timeout)
	case <-s.proxy.done:
		return nil, errors.New("端口映射已关闭")
	case <-s.done:
		return nil, errors.New("会话已关闭")
	}
}

// attach 绑定隧道连接；若会话已关闭则立即关闭连接并返回 false。
func (s *udpSession) attach(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	select {
	case <-s.done:
		_ = conn.Close()
		return false
	default:
	}
	s.conn = conn
	return true
}

// writeTunnel 把出站队列中的数据报逐帧写入隧道（公网 -> 内网）。
func (s *udpSession) writeTunnel() {
	for {
		select {
		case <-s.done:
			return
		case payload := <-s.sendCh:
			if err := protocol.WriteFrame(s.conn, payload); err != nil {
				if !netutil.IsClosedError(err) {
					s.logger.Debugf("UDP 隧道写入失败 (%s): %v", s.key, err)
				}
				s.close()
				return
			}
			s.touch()
			s.proxy.stats.BytesIn().Add(int64(len(payload)))
		}
	}
}

// readTunnel 从隧道读取内网应答并回写给公网来源（内网 -> 公网）。
func (s *udpSession) readTunnel() {
	defer s.close()

	for {
		payload, err := protocol.ReadFrame(s.conn)
		if err != nil {
			if !netutil.IsClosedError(err) {
				s.logger.Debugf("UDP 隧道读取结束 (%s): %v", s.key, err)
			}
			return
		}
		s.touch()

		if _, err := s.proxy.udpConn.WriteToUDP(payload, s.addr); err != nil {
			if !netutil.IsClosedError(err) {
				s.logger.Warnf("回写 UDP 数据报失败 (%s): %v", s.key, err)
			}
			return
		}
		s.proxy.stats.BytesOut().Add(int64(len(payload)))
	}
}

// close 关闭会话并回收隧道资源，可重复调用。
func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)

		s.mu.Lock()
		if s.conn != nil {
			_ = s.conn.Close()
		}
		s.mu.Unlock()

		s.proxy.removeUDPSession(s)
		s.proxy.stats.CloseConn()
		s.logger.Debugf("UDP 会话已关闭: %s", s.key)
	})
}

// readUDP 是 UDP 映射的接收循环：按来源地址维护会话并转发数据报。
func (p *proxy) readUDP() {
	buf := make([]byte, protocol.MaxFrameSize)
	for {
		n, addr, err := p.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-p.done:
				// 映射关闭导致的正常退出。
				return
			default:
			}
			p.logger.Warnf("读取 UDP 数据报失败: %v", err)
			continue
		}
		if n == 0 {
			continue
		}

		s := p.getOrCreateUDPSession(addr)
		if s == nil {
			continue
		}
		s.touch()
		// enqueue 内部会复制数据报，因此可以复用 buf。
		s.enqueue(buf[:n])
	}
}

// getOrCreateUDPSession 查找来源对应的会话，不存在则新建并异步建立隧道。
//
// 该方法只在 readUDP 这一单一协程中调用，因此对 udpSessions 的
// "查后即建" 不存在并发竞争。
func (p *proxy) getOrCreateUDPSession(addr *net.UDPAddr) *udpSession {
	key := addr.String()

	p.mu.Lock()
	if s, ok := p.udpSessions[key]; ok {
		p.mu.Unlock()
		return s
	}
	p.mu.Unlock()

	s := newUDPSession(p, key, addr)
	p.addUDPSession(s)
	p.stats.OpenConn()
	p.logger.Debugf("新建 UDP 会话: %s", key)

	// 建立隧道可能耗时，放入独立协程以免阻塞接收循环。
	go s.run()
	return s
}

// cleanUDP 周期性回收空闲超时的 UDP 会话，避免隧道连接长期占用。
func (p *proxy) cleanUDP() {
	idle := p.srv.cfg.UDPIdleDuration()
	interval := idle / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.reapUDPSessions(idle)
		}
	}
}

// reapUDPSessions 关闭空闲超过 idle 的会话。
func (p *proxy) reapUDPSessions(idle time.Duration) {
	deadline := time.Now().Add(-idle)

	p.mu.Lock()
	var stale []*udpSession
	for _, s := range p.udpSessions {
		if s.lastActiveAt().Before(deadline) {
			stale = append(stale, s)
		}
	}
	p.mu.Unlock()

	// 在锁外关闭会话，避免 close 回调 removeUDPSession 时发生死锁。
	for _, s := range stale {
		p.logger.Debugf("回收空闲 UDP 会话: %s", s.key)
		s.close()
	}
}
