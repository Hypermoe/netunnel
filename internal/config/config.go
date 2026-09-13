// Package config 负责服务端 / 客户端配置文件的加载、默认值填充与合法性校验。
//
// 配置文件使用 YAML 格式，示例见项目 configs 目录下的 server.yaml 与 client.yaml。
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"hypermoe/netunnel/internal/protocol"
)

// ServerConfig 是服务端配置。
type ServerConfig struct {
	// BindAddr 控制连接监听地址，0.0.0.0 表示所有网卡。
	BindAddr string `yaml:"bind_addr"`
	// BindPort 控制连接监听端口，客户端需连接该端口。
	BindPort int `yaml:"bind_port"`
	// Token 客户端接入令牌，为空表示不校验（不建议在生产环境使用）。
	Token string `yaml:"token"`
	// LogLevel 日志级别: debug/info/warn/error。
	LogLevel string `yaml:"log_level"`
	// LogFile 日志文件路径，为空时输出到标准输出。
	LogFile string `yaml:"log_file"`
	// HeartbeatTimeout 心跳超时时间（秒）。超过该时间未收到任何控制报文即判定客户端离线。
	HeartbeatTimeout int `yaml:"heartbeat_timeout"`
	// HandshakeTimeout 握手超时时间（秒）。
	HandshakeTimeout int `yaml:"handshake_timeout"`
	// WorkConnTimeout 服务端等待客户端工作连接的超时时间（秒）。
	WorkConnTimeout int `yaml:"work_conn_timeout"`
	// UDPIdleTimeout UDP 会话空闲超时时间（秒），超时后回收隧道资源。
	UDPIdleTimeout int `yaml:"udp_idle_timeout"`
	// MaxClients 允许同时在线的客户端数量上限，0 表示不限制。
	MaxClients int `yaml:"max_clients"`

	// configPath 记录配置文件所在路径，便于把 log_file 等相对路径解析为绝对路径。
	configPath string `yaml:"-"`
}

// ClientConfig 是客户端配置。
type ClientConfig struct {
	// ServerAddr 服务端地址（域名或 IP）。
	ServerAddr string `yaml:"server_addr"`
	// ServerPort 服务端控制端口。
	ServerPort int `yaml:"server_port"`
	// Token 与服务端一致的接入令牌。
	Token string `yaml:"token"`
	// ClientID 客户端唯一标识，为空时使用主机名。
	ClientID string `yaml:"client_id"`
	// LogLevel 日志级别: debug/info/warn/error。
	LogLevel string `yaml:"log_level"`
	// LogFile 日志文件路径，为空时输出到标准输出。
	LogFile string `yaml:"log_file"`
	// ReconnectInterval 断线重连的基础间隔（秒），实际采用指数退避。
	ReconnectInterval int `yaml:"reconnect_interval"`
	// DialTimeout 与服务端建立连接的超时时间（秒）。
	DialTimeout int `yaml:"dial_timeout"`
	// HeartbeatInterval 心跳发送间隔（秒），应显著小于服务端 heartbeat_timeout。
	HeartbeatInterval int `yaml:"heartbeat_interval"`
	// WorkConnTimeout 建立工作连接的超时时间（秒）。
	WorkConnTimeout int `yaml:"work_conn_timeout"`
	// UDPIdleTimeout UDP 隧道空闲超时时间（秒）。
	UDPIdleTimeout int `yaml:"udp_idle_timeout"`
	// Proxies 端口映射规则列表。
	Proxies []ProxyConfig `yaml:"proxies"`

	configPath string `yaml:"-"`
}

// ProxyConfig 是单条端口映射规则。
type ProxyConfig struct {
	// Name 规则名称，同一客户端内唯一。
	Name string `yaml:"name"`
	// Type 代理类型: tcp / udp。
	Type string `yaml:"type"`
	// LocalIP 内网服务地址（从客户端视角可达）。
	LocalIP string `yaml:"local_ip"`
	// LocalPort 内网服务端口。
	LocalPort int `yaml:"local_port"`
	// RemotePort 服务端对外暴露的端口。
	RemotePort int `yaml:"remote_port"`
}

// Spec 将配置转换为协议层的映射描述。
func (p ProxyConfig) Spec() protocol.ProxySpec {
	return protocol.ProxySpec{
		Name:       p.Name,
		Type:       p.Type,
		LocalIP:    p.LocalIP,
		LocalPort:  p.LocalPort,
		RemotePort: p.RemotePort,
	}
}

// LocalAddr 返回内网服务的 host:port。
func (p ProxyConfig) LocalAddr() string {
	return net.JoinHostPort(p.LocalIP, fmt.Sprintf("%d", p.LocalPort))
}

// 各配置项的默认值。
const (
	defaultServerBindAddr = "0.0.0.0"
	defaultServerBindPort = 7000
	defaultHeartbeatTO    = 90
	defaultHandshakeTO    = 10
	defaultWorkConnTO     = 10
	defaultUDPIdleTO      = 60
	defaultReconnectIv    = 5
	defaultDialTO         = 10
	defaultHeartbeatIv    = 30
)

// LoadServer 读取并校验服务端配置。
func LoadServer(path string) (*ServerConfig, error) {
	cfg := &ServerConfig{}
	if err := loadYAML(path, cfg); err != nil {
		return nil, err
	}
	cfg.configPath = path
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("服务端配置校验失败: %w", err)
	}
	return cfg, nil
}

// LoadClient 读取并校验客户端配置。
func LoadClient(path string) (*ClientConfig, error) {
	cfg := &ClientConfig{}
	if err := loadYAML(path, cfg); err != nil {
		return nil, err
	}
	cfg.configPath = path
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("客户端配置校验失败: %w", err)
	}
	return cfg, nil
}

// loadYAML 读取 YAML 文件并反序列化，使用严格模式以便及时发现拼写错误的字段。
func loadYAML(path string, out any) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("配置文件路径不能为空")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	}
	if len(data) == 0 {
		return fmt.Errorf("配置文件 %s 内容为空", path)
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
	}
	return nil
}

// applyDefaults 为未显式配置的字段填充默认值。
func (c *ServerConfig) applyDefaults() {
	if c.BindAddr == "" {
		c.BindAddr = defaultServerBindAddr
	}
	if c.BindPort == 0 {
		c.BindPort = defaultServerBindPort
	}
	if c.HeartbeatTimeout <= 0 {
		c.HeartbeatTimeout = defaultHeartbeatTO
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = defaultHandshakeTO
	}
	if c.WorkConnTimeout <= 0 {
		c.WorkConnTimeout = defaultWorkConnTO
	}
	if c.UDPIdleTimeout <= 0 {
		c.UDPIdleTimeout = defaultUDPIdleTO
	}
	c.LogFile = c.resolvePath(c.LogFile)
}

// applyDefaults 为客户端未显式配置的字段填充默认值。
func (c *ClientConfig) applyDefaults() error {
	if c.ServerPort == 0 {
		c.ServerPort = defaultServerBindPort
	}
	if c.ReconnectInterval <= 0 {
		c.ReconnectInterval = defaultReconnectIv
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = defaultDialTO
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = defaultHeartbeatIv
	}
	if c.WorkConnTimeout <= 0 {
		c.WorkConnTimeout = defaultWorkConnTO
	}
	if c.UDPIdleTimeout <= 0 {
		c.UDPIdleTimeout = defaultUDPIdleTO
	}
	if c.ClientID == "" {
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("获取主机名作为 client_id 失败，请在配置中显式指定 client_id: %w", err)
		}
		c.ClientID = host
	}
	c.LogFile = c.resolvePath(c.LogFile)
	return nil
}

// resolvePath 将相对路径解析为相对于配置文件所在目录的绝对路径，
// 保证从任意工作目录启动时行为一致。
func (c *ServerConfig) resolvePath(p string) string { return resolvePath(c.configPath, p) }
func (c *ClientConfig) resolvePath(p string) string { return resolvePath(c.configPath, p) }

func resolvePath(configPath, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	base := filepath.Dir(configPath)
	if base == "" || base == "." {
		return p
	}
	return filepath.Join(base, p)
}

// Validate 校验服务端配置的合法性。
func (c *ServerConfig) Validate() error {
	if err := validateHostPort("bind_addr/bind_port", c.BindAddr, c.BindPort); err != nil {
		return err
	}
	if c.BindAddr == "" {
		return errors.New("bind_addr 不能为空")
	}
	return nil
}

// Warnings 返回非阻断性的配置提示，由调用方决定如何展示。
func (c *ServerConfig) Warnings() []string {
	var warns []string
	if c.Token == "" {
		warns = append(warns, "未配置 token，任何客户端都可接入，建议在生产环境配置令牌")
	}
	return warns
}

// Validate 校验客户端配置的合法性。
func (c *ClientConfig) Validate() error {
	if strings.TrimSpace(c.ServerAddr) == "" {
		return errors.New("server_addr 不能为空")
	}
	if err := validatePort("server_port", c.ServerPort); err != nil {
		return err
	}
	if len(c.Proxies) == 0 {
		return errors.New("至少需要配置一条端口映射规则 (proxies)")
	}

	names := make(map[string]struct{}, len(c.Proxies))
	ports := make(map[string]string, len(c.Proxies))
	for i, p := range c.Proxies {
		if err := protocol.ValidateProxySpec(p.Spec()); err != nil {
			return fmt.Errorf("第 %d 条映射配置非法: %w", i+1, err)
		}
		if _, dup := names[p.Name]; dup {
			return fmt.Errorf("映射名称 %q 重复", p.Name)
		}
		names[p.Name] = struct{}{}

		// 同一协议下的同一个公网端口不能被两条规则同时占用。
		key := fmt.Sprintf("%s/%d", p.Type, p.RemotePort)
		if other, dup := ports[key]; dup {
			return fmt.Errorf("映射 %q 与 %q 占用了相同的公网端口 %d", p.Name, other, p.RemotePort)
		}
		ports[key] = p.Name
	}
	return nil
}

// Proxy 按名称查找映射规则。
func (c *ClientConfig) Proxy(name string) (ProxyConfig, bool) {
	for _, p := range c.Proxies {
		if p.Name == name {
			return p, true
		}
	}
	return ProxyConfig{}, false
}

// ServerAddrPort 返回服务端控制连接的 host:port。
func (c *ClientConfig) ServerAddrPort() string {
	return net.JoinHostPort(c.ServerAddr, fmt.Sprintf("%d", c.ServerPort))
}

// ReconnectDuration 返回重连基础间隔。
func (c *ClientConfig) ReconnectDuration() time.Duration {
	return time.Duration(c.ReconnectInterval) * time.Second
}

// DialDuration 返回拨号超时时间。
func (c *ClientConfig) DialDuration() time.Duration {
	return time.Duration(c.DialTimeout) * time.Second
}

// HeartbeatDuration 返回心跳间隔。
func (c *ClientConfig) HeartbeatDuration() time.Duration {
	return time.Duration(c.HeartbeatInterval) * time.Second
}

// WorkConnDuration 返回工作连接超时时间。
func (c *ClientConfig) WorkConnDuration() time.Duration {
	return time.Duration(c.WorkConnTimeout) * time.Second
}

// UDPIdleDuration 返回 UDP 会话空闲超时时间。
func (c *ClientConfig) UDPIdleDuration() time.Duration {
	return time.Duration(c.UDPIdleTimeout) * time.Second
}

// HeartbeatTimeoutDuration 返回心跳超时时间。
func (s *ServerConfig) HeartbeatTimeoutDuration() time.Duration {
	return time.Duration(s.HeartbeatTimeout) * time.Second
}

// HandshakeDuration 返回握手超时时间。
func (s *ServerConfig) HandshakeDuration() time.Duration {
	return time.Duration(s.HandshakeTimeout) * time.Second
}

// WorkConnDuration 返回工作连接超时时间。
func (s *ServerConfig) WorkConnDuration() time.Duration {
	return time.Duration(s.WorkConnTimeout) * time.Second
}

// UDPIdleDuration 返回 UDP 会话空闲超时时间。
func (s *ServerConfig) UDPIdleDuration() time.Duration {
	return time.Duration(s.UDPIdleTimeout) * time.Second
}

// ConfigPath 返回配置文件路径。
func (s *ServerConfig) ConfigPath() string { return s.configPath }

// ConfigPath 返回配置文件路径。
func (c *ClientConfig) ConfigPath() string { return c.configPath }

// validatePort 校验端口范围。
func validatePort(field string, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%s 非法: %d (取值范围 1-65535)", field, port)
	}
	return nil
}

// validateHostPort 同时校验主机与端口配置。
func validateHostPort(field, host string, port int) error {
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%s 的地址不能为空", field)
	}
	return validatePort(field, port)
}
