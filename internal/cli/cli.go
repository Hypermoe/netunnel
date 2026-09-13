// Package cli 实现 netunnel 的命令行入口。
//
// 命令形态：
//
//	netunnel <server|client> -c <配置文件>
//
// 进程在前台运行，运行中可使用的控制台命令（status / help / quit）说明见
// waitForShutdown；需常驻时请配合 nohup / screen / systemd 等工具。
package cli

import (
	"fmt"
	"os"

	"hypermoe/netunnel/internal/version"
)

// usageText 是顶层帮助信息。
const usageText = `netunnel - 基于 Golang 的 TCP/UDP 内网穿透工具

用法:
  netunnel <角色> -c <配置文件>

角色:
  server    服务端：监听公网端口，转发公网流量到客户端
  client    客户端：把内网服务映射到服务端公网端口

参数:
  -c, --config <路径>   配置文件路径 (必填，示例见 configs/server.yaml)
  -h, --help            显示帮助
  -v, --version         显示版本

控制台命令 (运行中可用):
  status     打印当前运行状态
  help       显示控制台命令提示
  quit       优雅退出 (等价于 Ctrl+C)

示例:
  netunnel server -c configs/server.yaml
  netunnel client -c configs/client.yaml
`

// Main 是命令行入口，返回进程退出码。
func Main(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}

	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(usageText)
		return 0
	case "-v", "--version", "version":
		fmt.Printf("netunnel %s\n", version.Version)
		return 0
	case "server":
		return runRole("server", args[1:])
	case "client":
		return runRole("client", args[1:])
	default:
		fmt.Fprintf(os.Stderr, "未知角色: %s\n\n", args[0])
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
}

// formatBytes 把字节数格式化为易读形式。
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	value := float64(n)
	units := []string{"KB", "MB", "GB", "TB"}
	for _, u := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f%s", value, u)
		}
	}
	return fmt.Sprintf("%.1fPB", value/unit)
}

// formatDuration 把秒数格式化为易读形式。
func formatDuration(seconds int64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm%ds", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%dh%dm", seconds/3600, (seconds%3600)/60)
}
