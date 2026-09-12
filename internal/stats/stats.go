// Package stats 提供端口映射的运行统计，供管理接口展示。
package stats

import (
	"sync/atomic"
	"time"
)

// ProxySnapshot 是某一时刻的统计快照，可直接序列化为 JSON。
type ProxySnapshot struct {
	// CurrentConns 当前活跃连接（TCP）或会话（UDP）数量。
	CurrentConns int64 `json:"current_conns"`
	// TotalConns 累计处理连接/会话数量。
	TotalConns int64 `json:"total_conns"`
	// BytesIn 公网侧发送到内网的字节数。
	BytesIn int64 `json:"bytes_in"`
	// BytesOut 内网侧返回给公网的字节数。
	BytesOut int64 `json:"bytes_out"`
}

// Proxy 是并发安全的计数器集合。
type Proxy struct {
	currentConns atomic.Int64
	totalConns   atomic.Int64
	bytesIn      atomic.Int64
	bytesOut     atomic.Int64
}

// OpenConn 记录一次连接/会话的建立。
func (p *Proxy) OpenConn() {
	p.currentConns.Add(1)
	p.totalConns.Add(1)
}

// CloseConn 记录一次连接/会话的关闭，计数不会降到 0 以下。
func (p *Proxy) CloseConn() {
	p.currentConns.Add(-1)
}

// BytesIn 返回公网 -> 内网字节计数器的指针，供转发层直接累加，避免每包加锁。
func (p *Proxy) BytesIn() *atomic.Int64 { return &p.bytesIn }

// BytesOut 返回内网 -> 公网字节计数器的指针。
func (p *Proxy) BytesOut() *atomic.Int64 { return &p.bytesOut }

// Snapshot 返回当前统计快照。
func (p *Proxy) Snapshot() ProxySnapshot {
	return ProxySnapshot{
		CurrentConns: p.currentConns.Load(),
		TotalConns:   p.totalConns.Load(),
		BytesIn:      p.bytesIn.Load(),
		BytesOut:     p.bytesOut.Load(),
	}
}

// Uptime 返回从 start 到现在的秒数，start 为零值时返回 0。
func Uptime(start time.Time) int64 {
	if start.IsZero() {
		return 0
	}
	return int64(time.Since(start).Seconds())
}
