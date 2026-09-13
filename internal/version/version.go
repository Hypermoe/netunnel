// Package version 保存程序版本号。
//
// 版本号可在构建时通过 -ldflags 注入，例如：
//
//	go build -ldflags "-X hypermoe/netunnel/internal/version.Version=1.2.0" ./cmd/netunnel
package version

// Version 是当前程序版本号。
var Version = "1.1.0"
