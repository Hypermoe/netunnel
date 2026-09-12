// Package protocol 定义客户端与服务端之间的控制协议。
//
// 协议分层：
//
//  1. 握手阶段：所有报文均为 JSON，采用 4 字节大端长度前缀 + JSON 负载的帧格式
//     （见 WriteMessage / ReadMessage）。
//  2. 数据阶段：
//     - TCP 代理：握手完成后工作连接直接进入裸流模式，双向复制原始字节。
//     - UDP 代理：握手完成后工作连接进入定长帧模式，每个 UDP 数据报
//     以 4 字节大端长度前缀 + 负载 的方式传输（见 WriteFrame / ReadFrame），
//     以此在可靠的 TCP 隧道上保留数据报边界，实现 UDP 的可靠投递。
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// 报文类型常量。
const (
	// TypeLogin 客户端 -> 服务端：控制连接登录认证。
	TypeLogin = "login"
	// TypeLoginResp 服务端 -> 客户端：登录结果。
	TypeLoginResp = "login_resp"
	// TypeHeartbeat 双向心跳，服务端收到后原样回发，用于探测链路存活。
	TypeHeartbeat = "heartbeat"
	// TypeNewProxy 服务端 -> 客户端：有新的公网连接接入，要求客户端建立工作连接。
	TypeNewProxy = "new_proxy"
	// TypeNewWorkConn 客户端 -> 服务端：工作连接握手，携带要对接的会话 ID。
	TypeNewWorkConn = "new_work_conn"
	// TypeNewWorkConnResp 服务端 -> 客户端：工作连接握手结果。
	TypeNewWorkConnResp = "new_work_conn_resp"
	// TypeStop 服务端 -> 客户端：通知客户端主动断开（如被管理员停止）。
	TypeStop = "stop"
)

// 代理类型常量。
const (
	// ProxyTypeTCP TCP 类型代理。
	ProxyTypeTCP = "tcp"
	// ProxyTypeUDP UDP 类型代理。
	ProxyTypeUDP = "udp"
)

// 响应码常量。
const (
	// CodeOK 表示操作成功。
	CodeOK = 0
	// CodeAuthFailed 表示令牌校验失败。
	CodeAuthFailed = 1
	// CodeClientExists 表示同 ID 客户端已在线。
	CodeClientExists = 2
	// CodeProxyError 表示端口映射创建失败（如端口被占用）。
	CodeProxyError = 3
	// CodeSessionNotFound 表示服务端已找不到对应的会话（通常已超时）。
	CodeSessionNotFound = 4
	// CodeInternalError 表示服务端内部错误。
	CodeInternalError = 5
)

// maxMessageSize 限制单个握手报文大小，防止恶意端构造超大报文导致内存耗尽。
const maxMessageSize = 64 * 1024

// MaxFrameSize 限制单个 UDP 数据报分帧后的最大长度。
const MaxFrameSize = 65535

// ProxySpec 描述一条端口映射规则，随登录报文上报给服务端。
type ProxySpec struct {
	// Name 映射规则名称，需在同一客户端内唯一。
	Name string `json:"name"`
	// Type 代理类型，取值为 "tcp" 或 "udp"。
	Type string `json:"type"`
	// LocalIP 内网服务地址。
	LocalIP string `json:"local_ip"`
	// LocalPort 内网服务端口。
	LocalPort int `json:"local_port"`
	// RemotePort 服务端对外暴露的端口。
	RemotePort int `json:"remote_port"`
}

// LocalAddr 返回内网服务的 host:port，便于日志与状态展示。
func (s ProxySpec) LocalAddr() string {
	return net.JoinHostPort(s.LocalIP, strconv.Itoa(s.LocalPort))
}

// Message 是控制协议的统一报文结构。
// 通过 Type 字段区分语义，其余字段按需使用（omitempty 保证报文紧凑）。
type Message struct {
	// Type 报文类型，见 TypeXXX 常量。
	Type string `json:"type"`
	// Token 登录令牌，仅 TypeLogin 使用。
	Token string `json:"token,omitempty"`
	// ClientID 客户端标识，仅 TypeLogin 使用；为空时由服务端分配。
	ClientID string `json:"client_id,omitempty"`
	// Version 客户端版本号，便于服务端排查兼容性问题。
	Version string `json:"version,omitempty"`
	// Timestamp 报文产生时间（Unix 秒），用于心跳时延观测。
	Timestamp int64 `json:"timestamp,omitempty"`
	// Proxies 客户端声明的端口映射规则，仅 TypeLogin 使用。
	Proxies []ProxySpec `json:"proxies,omitempty"`

	// Code 响应码，仅 XXXResp 类报文使用。
	Code int `json:"code,omitempty"`
	// Message 响应描述信息。
	Message string `json:"message,omitempty"`

	// ProxyName 映射规则名称，仅 TypeNewProxy / TypeNewWorkConn 使用。
	ProxyName string `json:"proxy_name,omitempty"`
	// SessionID 会话唯一标识，用于把公网连接与工作连接配对。
	SessionID string `json:"session_id,omitempty"`
	// RemoteAddr 公网访问方地址，仅 TypeNewProxy 使用，便于审计。
	RemoteAddr string `json:"remote_addr,omitempty"`
	// Protocol 代理协议类型，仅 TypeNewProxy 使用。
	Protocol string `json:"protocol,omitempty"`
}

// WriteMessage 以 4 字节长度前缀 + JSON 负载的格式写入一条报文。
func WriteMessage(w io.Writer, msg *Message) error {
	if msg == nil {
		return errors.New("protocol: 报文为空")
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("protocol: 序列化报文失败: %w", err)
	}
	if len(body) > maxMessageSize {
		return fmt.Errorf("protocol: 报文长度 %d 超过上限 %d", len(body), maxMessageSize)
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	// 先写头部再写负载；net.Conn 的 Write 语义保证头部不会被拆包丢弃。
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("protocol: 写入报文头失败: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("protocol: 写入报文负载失败: %w", err)
	}
	return nil
}

// ReadMessage 读取并解析一条报文。
func ReadMessage(r io.Reader) (*Message, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("protocol: 读取报文头失败: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxMessageSize {
		return nil, fmt.Errorf("protocol: 非法报文长度 %d", length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("protocol: 读取报文负载失败: %w", err)
	}

	msg := &Message{}
	if err := json.Unmarshal(body, msg); err != nil {
		return nil, fmt.Errorf("protocol: 解析报文失败: %w", err)
	}
	return msg, nil
}

// WriteFrame 写入一个数据报帧（4 字节大端长度前缀 + 负载），用于 UDP over TCP 隧道。
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("protocol: 数据报长度 %d 超过上限 %d", len(payload), MaxFrameSize)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))

	// 合并为一次写入，减少小包带来的系统调用开销。
	buf := make([]byte, 4+len(payload))
	copy(buf[:4], header[:])
	copy(buf[4:], payload)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("protocol: 写入数据帧失败: %w", err)
	}
	return nil
}

// ReadFrame 读取一个数据报帧并返回其负载。
// 返回的切片为新分配内存，调用方可以安全持有。
func ReadFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > MaxFrameSize {
		return nil, fmt.Errorf("protocol: 非法数据帧长度 %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("protocol: 读取数据帧失败: %w", err)
	}
	return payload, nil
}

// NewSessionID 生成 16 字节随机十六进制会话 ID，避免会话之间相互串扰。
func NewSessionID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("protocol: 生成会话 ID 失败: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// MustSessionID 生成会话 ID，用于调用方已经无法优雅处理错误的场景。
// 若系统熵源不可用则 panic，属于不可恢复的运行时错误。
func MustSessionID() string {
	id, err := NewSessionID()
	if err != nil {
		panic(err)
	}
	return id
}

// ValidateProxySpec 校验单条映射规则的必要字段是否合法。
func ValidateProxySpec(spec ProxySpec) error {
	if spec.Name == "" {
		return errors.New("映射规则名称不能为空")
	}
	switch spec.Type {
	case ProxyTypeTCP, ProxyTypeUDP:
	case "":
		return fmt.Errorf("映射 %q 未指定 type", spec.Name)
	default:
		return fmt.Errorf("映射 %q 的 type 非法: %q，仅支持 tcp/udp", spec.Name, spec.Type)
	}
	if spec.LocalIP == "" {
		return fmt.Errorf("映射 %q 未指定 local_ip", spec.Name)
	}
	if spec.LocalPort <= 0 || spec.LocalPort > 65535 {
		return fmt.Errorf("映射 %q 的 local_port 非法: %d", spec.Name, spec.LocalPort)
	}
	if spec.RemotePort <= 0 || spec.RemotePort > 65535 {
		return fmt.Errorf("映射 %q 的 remote_port 非法: %d", spec.Name, spec.RemotePort)
	}
	return nil
}
