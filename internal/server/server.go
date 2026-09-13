// Package server 实现内网穿透服务端。
//
// 服务端承担两类监听：
//
//  1. 控制端口（cfg.BindPort）：接受客户端登录，维护长连接与心跳；
//  2. 公网映射端口（每条映射规则的 remote_port）：接收公网访问流量。
//
// 当公网有连接/数据到达时，服务端通过控制连接通知客户端，客户端随即
// 向控制端口发起一条"工作连接"；服务端按会话 ID 将公网连接与工作
// 连接配对后双向转发，从而实现内网服务的公网暴露。
package server

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"hypermoe/netunnel/internal/config"
	"hypermoe/netunnel/internal/log"
	"hypermoe/netunnel/internal/stats"
	"hypermoe/netunnel/internal/version"
)

// sendTimeout 是向客户端投递控制报文的最长等待时间。
// 超时即认为客户端异常，避免公网接入流程被单个客户端长时间阻塞。
const sendTimeout = 5 * time.Second

// Server 是服务端实例。
type Server struct {
	cfg       *config.ServerConfig
	logger    *log.Logger
	startTime time.Time

	// mu 保护以下所有注册表。
	mu sync.RWMutex
	// clients 以客户端 ID 为索引保存在线客户端。
	clients map[string]*client
	// proxies 以映射名称为索引保存已建立的端口映射。
	proxies map[string]*proxy
	// portOwner 记录公网端口的占用情况，键为 "tcp/6000" 形式。
	portOwner map[string]string
	// pending 记录等待工作连接接入的会话。
	pending map[string]*pending
	// closed 标记服务端是否已停止，用于拒绝停止后的新请求。
	closed bool

	listener net.Listener

	stopOnce sync.Once
	wg       sync.WaitGroup
	done     chan struct{}
}

// New 创建服务端实例。
func New(cfg *config.ServerConfig, logger *log.Logger) *Server {
	return &Server{
		cfg:       cfg,
		logger:    logger,
		clients:   make(map[string]*client),
		proxies:   make(map[string]*proxy),
		portOwner: make(map[string]string),
		pending:   make(map[string]*pending),
		done:      make(chan struct{}),
	}
}

// Start 启动服务端：绑定控制端口并开始接受客户端连接。
// 该方法在绑定完成后立即返回，实际服务在后台 goroutine 中运行。
func (s *Server) Start() error {
	addr := net.JoinHostPort(s.cfg.BindAddr, fmt.Sprintf("%d", s.cfg.BindPort))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("控制端口监听 %s 失败: %w", addr, err)
	}
	s.listener = listener
	s.startTime = time.Now()

	s.logger.Infof("服务端已启动，控制端口: %s", listener.Addr())

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Stop 优雅停止服务端：关闭监听、断开所有客户端并回收端口映射。
// 可重复调用。
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()

		close(s.done)
		if s.listener != nil {
			_ = s.listener.Close()
		}

		// 断开所有客户端，其关联的端口映射会随之释放。
		s.mu.RLock()
		clients := make([]*client, 0, len(s.clients))
		for _, c := range s.clients {
			clients = append(clients, c)
		}
		s.mu.RUnlock()
		for _, c := range clients {
			c.close()
		}

		s.wg.Wait()
		s.logger.Infof("服务端已停止")
	})
}

// Done 返回一个在服务端停止时关闭的通道，供上层等待退出信号。
func (s *Server) Done() <-chan struct{} { return s.done }

// acceptLoop 接受控制端口上的所有连接。
func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				// 正常关闭导致 Accept 返回错误。
				return
			default:
			}
			// 临时性错误（如文件描述符耗尽）不应终止整个服务。
			s.logger.Warnf("接受连接失败: %v", err)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

// 注册表操作 ------------------------------------------------------------------

// registerClient 注册在线客户端，若同 ID 客户端已存在则返回错误。
func (s *Server) registerClient(c *client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("服务端正在停止")
	}
	if s.cfg.MaxClients > 0 && len(s.clients) >= s.cfg.MaxClients {
		return fmt.Errorf("在线客户端数量已达上限 %d", s.cfg.MaxClients)
	}
	if _, exists := s.clients[c.id]; exists {
		return fmt.Errorf("客户端 ID %q 已在线", c.id)
	}
	s.clients[c.id] = c
	return nil
}

// unregisterClient 摘除客户端，并释放其持有的全部端口映射。
func (s *Server) unregisterClient(c *client) {
	s.mu.Lock()
	if cur, ok := s.clients[c.id]; ok && cur == c {
		delete(s.clients, c.id)
	}
	s.mu.Unlock()

	c.closeProxies()
}

// claimPort 占用一个公网端口，返回错误表示已被其他映射占用。
func (s *Server) claimPort(key, proxyName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner, exists := s.portOwner[key]; exists {
		return fmt.Errorf("公网端口已被映射 %q 占用", owner)
	}
	s.portOwner[key] = proxyName
	return nil
}

// releasePort 释放公网端口占用。
func (s *Server) releasePort(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.portOwner, key)
}

// registerProxy 登记一条已就绪的端口映射。
func (s *Server) registerProxy(p *proxy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proxies[p.name] = p
}

// unregisterProxy 移除端口映射登记。
func (s *Server) unregisterProxy(p *proxy) {
	s.mu.Lock()
	if cur, ok := s.proxies[p.name]; ok && cur == p {
		delete(s.proxies, p.name)
	}
	s.mu.Unlock()
}

// 状态查询 --------------------------------------------------------------------

// StatusSnapshot 是服务端运行状态快照，供前台控制台展示。
type StatusSnapshot struct {
	Role          string         `json:"role"`
	Version       string         `json:"version"`
	Bind          string         `json:"bind"`
	StartTime     string         `json:"start_time"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	ClientCount   int            `json:"client_count"`
	ProxyCount    int            `json:"proxy_count"`
	Clients       []ClientStatus `json:"clients"`
}

// ClientStatus 描述一个在线客户端及其映射的运行情况。
type ClientStatus struct {
	ClientID     string        `json:"client_id"`
	RemoteAddr   string        `json:"remote_addr"`
	ConnectedAt  string        `json:"connected_at"`
	UptimeSecond int64         `json:"uptime_seconds"`
	Proxies      []ProxyStatus `json:"proxies"`
}

// ProxyStatus 描述单条映射规则的运行情况。
type ProxyStatus struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	RemoteAddr   string `json:"remote_addr"`
	LocalAddr    string `json:"local_addr"`
	Status       string `json:"status"`
	CurrentConns int64  `json:"current_conns"`
	TotalConns   int64  `json:"total_conns"`
	BytesIn      int64  `json:"bytes_in"`
	BytesOut     int64  `json:"bytes_out"`
}

// Status 返回服务端当前状态快照。
func (s *Server) Status() StatusSnapshot {
	s.mu.RLock()
	clients := make([]*client, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, c)
	}
	proxyCount := len(s.proxies)
	s.mu.RUnlock()

	snapshot := StatusSnapshot{
		Role:          "server",
		Version:       version.Version,
		Bind:          s.bindAddr(),
		StartTime:     s.startTime.Format(time.RFC3339),
		UptimeSeconds: stats.Uptime(s.startTime),
		ClientCount:   len(clients),
		ProxyCount:    proxyCount,
		Clients:       make([]ClientStatus, 0, len(clients)),
	}
	for _, c := range clients {
		snapshot.Clients = append(snapshot.Clients, c.status())
	}
	return snapshot
}

// bindAddr 返回控制端口的实际监听地址。
func (s *Server) bindAddr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return net.JoinHostPort(s.cfg.BindAddr, fmt.Sprintf("%d", s.cfg.BindPort))
}
