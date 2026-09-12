// Package netutil 提供连接转发与底层网络参数调整的通用工具。
package netutil

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// Join 在 a、b 两个连接之间双向复制数据，任意一端结束后关闭双方。
//
// aToB、bToA 为非空的原子计数器时，会分别累加 a->b、b->a 的字节数，
// 用于统计端口映射的上下行流量；调用方也可传入 nil 表示不统计。
//
// 复制过程中对可半关闭的连接执行 CloseWrite，使 HTTP、Redis 等依赖
// 连接结束（EOF）语义的协议能够正常感知对端关闭，提升 TCP 代理的稳定性。
func Join(a, b net.Conn, aToB, bToA *atomic.Int64) {
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		proxyCopy(a, b, aToB)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		proxyCopy(b, a, bToA)
	}()

	// 等待两个方向都结束，确保数据被完整转发后再释放连接。
	<-done
	<-done
	closeConn(a)
	closeConn(b)
}

// proxyCopy 单向复制数据，并在复制结束后对目标连接执行半关闭。
func proxyCopy(dst, src net.Conn, counter *atomic.Int64) {
	var reader io.Reader = src
	if counter != nil {
		reader = &countingReader{r: src, counter: counter}
	}
	// 复制失败通常源于对端关闭连接，属于正常现象，无需向上层暴露错误。
	_, _ = io.Copy(dst, reader)

	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		closeConn(dst)
	}
	if cr, ok := src.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
	}
}

// countingReader 在读取时累加字节数。
type countingReader struct {
	r       io.Reader
	counter *atomic.Int64
}

// Read 实现 io.Reader，并在成功读取后累加计数。
func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.counter != nil {
		c.counter.Add(int64(n))
	}
	return n, err
}

// closeConn 关闭连接，重复关闭产生的错误无需上报。
func closeConn(c net.Conn) {
	if c == nil {
		return
	}
	_ = c.Close()
}

// IsClosedError 判断错误是否表示连接已关闭，用于过滤正常关闭产生的噪音日志。
func IsClosedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	msg := err.Error()
	// 兼容不同平台下连接被对端关闭时返回的文本差异。
	for _, s := range []string{
		"use of closed network connection",
		"connection reset by peer",
		"broken pipe",
		"forcibly closed",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// SetKeepAlive 开启 TCP 连接的保活探测。
//
// TCP 长连接在中间设备（NAT、防火墙）长时间空闲时可能被静默回收，
// 开启保活并缩短探测周期有助于尽早发现失效链路，配合心跳机制提升稳定性。
func SetKeepAlive(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return
	}
	// 30 秒无数据即开始探测，多数系统默认值远大于该值。
	_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	_ = tcpConn.SetNoDelay(true)
}
