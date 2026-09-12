// Command netunnel 是内网穿透工具的进程入口。
//
// 支持 TCP 与 UDP 两种传输协议，通过服务端 / 客户端架构把内网服务端口
// 映射到公网服务器。具体用法见：
//
//	netunnel -h
package main

import (
	"os"

	"netunnel/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
