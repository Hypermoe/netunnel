package cli

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"hypermoe/netunnel/internal/client"
	"hypermoe/netunnel/internal/config"
	"hypermoe/netunnel/internal/log"
	"hypermoe/netunnel/internal/server"
)

// 退出码约定。
const (
	// exitOK 表示操作成功。
	exitOK = 0
	// exitFailure 表示操作失败（配置错误、启动失败等）。
	exitFailure = 1
	// exitUsage 表示命令行用法错误。
	exitUsage = 2
)

// options 是子命令的命令行参数。
type options struct {
	// configPath 配置文件路径，必填。
	configPath string
	// help 是否请求显示帮助。
	help bool
}

// roleMeta 汇总服务端与客户端在命令行层面共用的信息。
type roleMeta struct {
	// role 角色名称（server / client）。
	role string
	// logLevel 日志级别字符串。
	logLevel string
	// logFile 日志文件路径，为空表示标准输出。
	logFile string
	// warnings 非阻断性配置提示。
	warnings []string
}

// runRole 解析参数并启动指定角色。
func runRole(role string, args []string) int {
	opts, err := parseOptions(role, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析参数失败: %v\n", err)
		return exitUsage
	}
	if opts.help {
		fmt.Print(roleUsage(role))
		return exitOK
	}
	if strings.TrimSpace(opts.configPath) == "" {
		fmt.Fprintln(os.Stderr, "错误: 必须通过 -c/--config 指定配置文件")
		fmt.Fprint(os.Stderr, roleUsage(role))
		return exitUsage
	}

	return runStart(role, opts)
}

// parseOptions 解析角色参数。同时接受短名与长名，便于书写。
func parseOptions(role string, args []string) (*options, error) {
	opts := &options{}

	fs := flag.NewFlagSet(role, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	// 关闭默认的用法输出，由调用方统一打印帮助信息。
	fs.Usage = func() {}

	fs.StringVar(&opts.configPath, "c", "", "配置文件路径")
	fs.StringVar(&opts.configPath, "config", "", "配置文件路径")
	fs.BoolVar(&opts.help, "h", false, "显示帮助")
	fs.BoolVar(&opts.help, "help", false, "显示帮助")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("存在多余参数: %s", strings.Join(fs.Args(), " "))
	}
	return opts, nil
}

// roleUsage 返回指定角色的帮助信息。
func roleUsage(role string) string {
	return fmt.Sprintf(`netunnel %s - %s

用法:
  netunnel %s -c <配置文件>

参数:
  -c, --config <路径>   配置文件路径 (必填)
  -h, --help            显示帮助

控制台命令 (运行中可用):
  status     打印当前运行状态
  help       显示控制台命令提示
  quit       优雅退出 (等价于 Ctrl+C)

退出码:
  0 成功   1 失败   2 用法错误
`, role, roleName(role), role)
}

// roleName 返回角色的中文名称。
func roleName(role string) string {
	if role == "server" {
		return "服务端"
	}
	return "客户端"
}

// serverMeta 从服务端配置提取公共信息。
func serverMeta(cfg *config.ServerConfig) roleMeta {
	return roleMeta{
		role:     "server",
		logLevel: cfg.LogLevel,
		logFile:  cfg.LogFile,
		warnings: cfg.Warnings(),
	}
}

// clientMeta 从客户端配置提取公共信息。
func clientMeta(cfg *config.ClientConfig) roleMeta {
	return roleMeta{
		role:     "client",
		logLevel: cfg.LogLevel,
		logFile:  cfg.LogFile,
	}
}

// runStart 加载配置并启动对应角色。
func runStart(role string, opts *options) int {
	if role == "server" {
		cfg, err := config.LoadServer(opts.configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return exitFailure
		}
		return startServer(cfg)
	}

	cfg, err := config.LoadClient(opts.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return exitFailure
	}
	return startClient(cfg)
}

// startServer 启动服务端并进入前台控制台。
func startServer(cfg *config.ServerConfig) int {
	meta := serverMeta(cfg)

	logger, err := newLogger("server", meta)
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化日志失败: %v\n", err)
		return exitFailure
	}
	defer func() { _ = logger.Close() }()
	logWarnings(logger, meta)

	srv := server.New(cfg, logger)
	if err := srv.Start(); err != nil {
		logger.Errorf("%v", err)
		return exitFailure
	}

	waitForShutdown(srv.Done(), logger, func() string { return renderServerStatus(srv.Status()) })
	srv.Stop()
	return exitOK
}

// startClient 启动客户端并进入前台控制台。
func startClient(cfg *config.ClientConfig) int {
	meta := clientMeta(cfg)

	logger, err := newLogger("client", meta)
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化日志失败: %v\n", err)
		return exitFailure
	}
	defer func() { _ = logger.Close() }()

	c := client.New(cfg, logger)
	if err := c.Start(); err != nil {
		logger.Errorf("%v", err)
		return exitFailure
	}

	waitForShutdown(c.Done(), logger, func() string { return renderClientStatus(c.Status()) })
	c.Stop()
	if err := c.FatalErr(); err != nil {
		return exitFailure
	}
	return exitOK
}

// newLogger 依据配置创建日志记录器。
func newLogger(prefix string, meta roleMeta) (*log.Logger, error) {
	level, err := log.ParseLevel(meta.logLevel)
	if err != nil {
		return nil, err
	}
	return log.New(prefix, level, meta.logFile)
}

// logWarnings 输出非阻断性的配置提示。
func logWarnings(logger *log.Logger, meta roleMeta) {
	for _, w := range meta.warnings {
		logger.Warnf("%s", w)
	}
}

// waitForShutdown 阻塞直至收到退出信号、控制台 quit 命令或服务自身结束。
//
// statusFn 返回当前状态的易读文本，供控制台 status 命令打印。
func waitForShutdown(done <-chan struct{}, logger *log.Logger, statusFn func() string) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	lineCh := make(chan string)
	go readConsoleLines(lineCh)

	printConsoleHint()
	for {
		select {
		case sig := <-sigCh:
			logger.Infof("收到信号 %v，开始退出", sig)
			return
		case <-done:
			logger.Infof("服务已停止")
			return
		case line, ok := <-lineCh:
			if !ok {
				// 标准输入已关闭（例如借助 nohup / screen 常驻运行），
				// 不再提供控制台交互，但进程继续运行直到收到信号或服务结束。
				lineCh = nil
				continue
			}
			if handleConsoleCommand(line, statusFn, logger) {
				return
			}
		}
	}
}

// readConsoleLines 逐行读取标准输入并写入通道，输入结束时关闭通道。
func readConsoleLines(ch chan<- string) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		ch <- scanner.Text()
	}
	close(ch)
}

// handleConsoleCommand 处理一条控制台命令，返回是否请求退出。
func handleConsoleCommand(line string, statusFn func() string, logger *log.Logger) bool {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return false
	case "status":
		fmt.Print(statusFn())
		return false
	case "help", "?":
		printConsoleHint()
		return false
	case "quit", "exit":
		logger.Infof("收到控制台退出指令，开始退出")
		return true
	default:
		fmt.Printf("未知命令: %s (输入 help 查看可用命令)\n", strings.TrimSpace(line))
		return false
	}
}

// printConsoleHint 打印控制台命令提示。
func printConsoleHint() {
	fmt.Println("已进入前台运行，输入 help 查看控制台命令 (status / help / quit)")
}

// proxyRow 是端口映射的统一展示结构，屏蔽服务端与客户端状态类型的差异。
type proxyRow struct {
	name     string
	typ      string
	local    string
	remote   string
	status   string
	current  int64
	total    int64
	bytesIn  int64
	bytesOut int64
}

// renderServerStatus 以易读格式渲染服务端状态。
func renderServerStatus(snap server.StatusSnapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "角色      : %s (%s)\n", snap.Role, snap.Version)
	fmt.Fprintf(&b, "控制监听  : %s\n", snap.Bind)
	fmt.Fprintf(&b, "启动时间  : %s\n", snap.StartTime)
	fmt.Fprintf(&b, "已运行    : %s\n", formatDuration(snap.UptimeSeconds))
	fmt.Fprintf(&b, "在线客户端: %d   端口映射: %d\n", snap.ClientCount, snap.ProxyCount)

	if len(snap.Clients) == 0 {
		b.WriteString("(暂无在线客户端)\n")
		return b.String()
	}
	for _, c := range snap.Clients {
		fmt.Fprintf(&b, "\n客户端 %s\n", c.ClientID)
		fmt.Fprintf(&b, "  来源地址: %s   连接时间: %s   在线: %s\n",
			c.RemoteAddr, c.ConnectedAt, formatDuration(c.UptimeSecond))
		rows := make([]proxyRow, 0, len(c.Proxies))
		for _, p := range c.Proxies {
			rows = append(rows, proxyRow{
				name:     p.Name,
				typ:      p.Type,
				local:    p.LocalAddr,
				remote:   p.RemoteAddr,
				status:   p.Status,
				current:  p.CurrentConns,
				total:    p.TotalConns,
				bytesIn:  p.BytesIn,
				bytesOut: p.BytesOut,
			})
		}
		b.WriteString(renderProxyTable(rows))
	}
	return b.String()
}

// renderClientStatus 以易读格式渲染客户端状态。
func renderClientStatus(snap client.StatusSnapshot) string {
	var b strings.Builder

	state := "未连接"
	if snap.Connected {
		state = "已连接"
	}
	fmt.Fprintf(&b, "角色      : %s (%s)\n", snap.Role, snap.Version)
	fmt.Fprintf(&b, "服务端    : %s\n", snap.Server)
	fmt.Fprintf(&b, "客户端 ID : %s\n", snap.ClientID)
	fmt.Fprintf(&b, "连接状态  : %s\n", state)
	if snap.ConnectedAt != "" {
		fmt.Fprintf(&b, "连接时间  : %s\n", snap.ConnectedAt)
	}
	fmt.Fprintf(&b, "启动时间  : %s\n", snap.StartTime)
	fmt.Fprintf(&b, "已运行    : %s\n", formatDuration(snap.UptimeSeconds))

	rows := make([]proxyRow, 0, len(snap.Proxies))
	for _, p := range snap.Proxies {
		rows = append(rows, proxyRow{
			name:     p.Name,
			typ:      p.Type,
			local:    p.LocalAddr,
			remote:   p.RemoteAddr,
			status:   p.Status,
			current:  p.CurrentConns,
			total:    p.TotalConns,
			bytesIn:  p.BytesIn,
			bytesOut: p.BytesOut,
		})
	}
	b.WriteString("端口映射  :\n")
	b.WriteString(renderProxyTable(rows))
	return b.String()
}

// renderProxyTable 以对齐的表格形式渲染端口映射。
func renderProxyTable(rows []proxyRow) string {
	if len(rows) == 0 {
		return "  (无端口映射)\n"
	}

	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  名称\t类型\t本地地址\t公网地址\t状态\t连接(当前/累计)\t流量(入/出)")
	for _, r := range rows {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%d/%d\t%s/%s\n",
			r.name, r.typ, r.local, r.remote, r.status, r.current, r.total,
			formatBytes(r.bytesIn), formatBytes(r.bytesOut))
	}
	_ = w.Flush()
	return b.String()
}
