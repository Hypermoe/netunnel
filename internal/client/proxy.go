package client

import (
	"fmt"
	"net"
	"time"

	"netunnel/internal/config"
	"netunnel/internal/netutil"
	"netunnel/internal/protocol"
	"netunnel/internal/stats"
)

// handleNewProxy 处理服务端下发的公网访问通知，按映射类型建立工作连接。
func (c *Client) handleNewProxy(msg *protocol.Message) {
	spec, ok := c.proxies[msg.ProxyName]
	if !ok {
		c.logger.Warnf("收到未知映射 %q 的接入请求 (会话 %s)", msg.ProxyName, msg.SessionID)
		return
	}

	select {
	case <-c.done:
		return
	default:
	}

	switch msg.Protocol {
	case protocol.ProxyTypeUDP:
		c.handleUDPWorkConn(msg, spec)
	case protocol.ProxyTypeTCP:
		c.handleTCPWorkConn(msg, spec)
	default:
		c.logger.Warnf("收到不支持的代理类型 %q (映射 %s)", msg.Protocol, spec.Name)
	}
}

// handleTCPWorkConn 处理一次 TCP 公网访问：
// 连接本地服务后建立工作连接，并在两者之间双向复制字节流。
func (c *Client) handleTCPWorkConn(msg *protocol.Message, spec config.ProxyConfig) {
	// 先连接本地服务：本地不可用时直接放弃，避免无谓地占用一条工作连接。
	localConn, err := net.DialTimeout("tcp", spec.LocalAddr(), c.cfg.DialDuration())
	if err != nil {
		c.logger.Warnf("连接本地服务 %s 失败 (映射 %s): %v", spec.LocalAddr(), spec.Name, err)
		return
	}
	netutil.SetKeepAlive(localConn)

	workConn, err := c.openWorkConn(msg.SessionID)
	if err != nil {
		c.logger.Warnf("建立工作连接失败 (映射 %s): %v", spec.Name, err)
		_ = localConn.Close()
		return
	}

	c.trackWorkConn(workConn)
	defer c.untrackWorkConn(workConn)

	c.logger.Debugf("TCP 连接已建立: %s <-> %s", spec.LocalAddr(), msg.RemoteAddr)

	st := c.proxyStat(spec.Name)
	if st == nil {
		netutil.Join(localConn, workConn, nil, nil)
		return
	}
	st.OpenConn()
	defer st.CloseConn()
	// 本地 -> 隧道 为出站流量，隧道 -> 本地 为入站流量，与服务端视角保持一致。
	netutil.Join(localConn, workConn, st.BytesOut(), st.BytesIn())
}

// handleUDPWorkConn 处理一次 UDP 公网访问。
//
// 每条 UDP 会话对应一条独立的工作连接与一个本地 UDP 套接字，
// 数据报以定长帧在 TCP 隧道上传输，从而获得可靠、有序、不重复的投递。
func (c *Client) handleUDPWorkConn(msg *protocol.Message, spec config.ProxyConfig) {
	udpAddr, err := net.ResolveUDPAddr("udp", spec.LocalAddr())
	if err != nil {
		c.logger.Warnf("解析本地 UDP 地址 %s 失败 (映射 %s): %v", spec.LocalAddr(), spec.Name, err)
		return
	}
	// 使用 connect 形式，确保只接收该内网服务返回的数据报。
	localConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		c.logger.Warnf("连接本地 UDP 服务 %s 失败 (映射 %s): %v", spec.LocalAddr(), spec.Name, err)
		return
	}
	defer func() { _ = localConn.Close() }()

	workConn, err := c.openWorkConn(msg.SessionID)
	if err != nil {
		c.logger.Warnf("建立 UDP 工作连接失败 (映射 %s): %v", spec.Name, err)
		return
	}

	c.trackWorkConn(workConn)
	defer c.untrackWorkConn(workConn)

	c.logger.Debugf("UDP 会话已建立: %s <-> %s", spec.LocalAddr(), msg.RemoteAddr)

	st := c.proxyStat(spec.Name)
	if st != nil {
		st.OpenConn()
		defer st.CloseConn()
	}

	// 两个方向各自独立运行，任一方向结束后关闭双方以释放资源。
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		c.tunnelToLocal(workConn, localConn, st)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		c.localToTunnel(localConn, workConn, st)
	}()

	<-done
	_ = workConn.Close()
	_ = localConn.Close()
	<-done
}

// tunnelToLocal 把隧道中的数据报帧写入本地 UDP 服务（公网 -> 内网）。
func (c *Client) tunnelToLocal(workConn net.Conn, localConn *net.UDPConn, st *stats.Proxy) {
	for {
		payload, err := protocol.ReadFrame(workConn)
		if err != nil {
			return
		}
		if _, err := localConn.Write(payload); err != nil {
			return
		}
		if st != nil {
			st.BytesIn().Add(int64(len(payload)))
		}
	}
}

// localToTunnel 把本地 UDP 服务的应答封装为数据报帧写入隧道（内网 -> 公网）。
func (c *Client) localToTunnel(localConn *net.UDPConn, workConn net.Conn, st *stats.Proxy) {
	buf := make([]byte, protocol.MaxFrameSize)
	for {
		// 已连接的 UDP 套接字每次 Read 恰好返回一个数据报，边界天然保留。
		n, err := localConn.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		if err := protocol.WriteFrame(workConn, buf[:n]); err != nil {
			return
		}
		if st != nil {
			st.BytesOut().Add(int64(n))
		}
	}
}

// openWorkConn 向服务端申请一条工作连接并完成握手，成功后返回该连接。
//
// 工作连接在数据阶段不使用 JSON 报文：TCP 直接传输裸字节流，
// UDP 则传输定长帧，因此握手报文之后连接即被移交给转发逻辑。
func (c *Client) openWorkConn(sessionID string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: c.cfg.DialDuration(), KeepAlive: 30 * time.Second}
	conn, err := dialer.Dial("tcp", c.cfg.ServerAddrPort())
	if err != nil {
		return nil, fmt.Errorf("连接服务端失败: %w", err)
	}

	req := &protocol.Message{Type: protocol.TypeNewWorkConn, SessionID: sessionID}
	if err := protocol.WriteMessage(conn, req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("发送工作连接请求失败: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(c.cfg.WorkConnDuration()))
	resp, err := protocol.ReadMessage(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("读取工作连接响应失败: %w", err)
	}
	if resp.Code != protocol.CodeOK {
		_ = conn.Close()
		return nil, fmt.Errorf("服务端拒绝工作连接: %s", resp.Message)
	}

	_ = conn.SetReadDeadline(time.Time{})
	netutil.SetKeepAlive(conn)
	return conn, nil
}
