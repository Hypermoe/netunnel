// Package log 提供并发安全的分级日志实现。
//
// 支持输出到标准输出或指定文件，日志格式为：
//
//	2006-01-02 15:04:05.000 [级别] [前缀] 内容
//
// 该实现刻意保持轻量，不引入第三方日志库，便于在服务端与客户端复用。
package log

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Level 表示日志级别，数值越小越详细。
type Level int

const (
	// LevelDebug 调试级别，输出最详细的信息。
	LevelDebug Level = iota
	// LevelInfo 普通信息级别。
	LevelInfo
	// LevelWarn 警告级别。
	LevelWarn
	// LevelError 错误级别。
	LevelError
)

// String 返回日志级别的可读名称。
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel 将配置中的字符串解析为 Level。
// 空字符串按 info 处理，未知取值返回错误，避免配置写错时静默生效。
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("无效的日志级别 %q，可选值: debug/info/warn/error", s)
	}
}

// Logger 是并发安全的分级日志记录器。
//
// 通过 WithPrefix 派生的记录器会共享同一把锁与同一个输出目标，
// 因此不同前缀的日志不会相互穿插。
type Logger struct {
	mu     *sync.Mutex
	level  Level
	out    io.Writer
	closer io.Closer
	prefix string
}

// New 创建日志记录器。
//
// filePath 为空时输出到标准输出；否则会以追加方式打开（必要时创建）该文件。
// 调用方应在退出前调用 Close 释放文件句柄。
func New(prefix string, level Level, filePath string) (*Logger, error) {
	l := &Logger{
		mu:     &sync.Mutex{},
		level:  level,
		out:    os.Stdout,
		prefix: prefix,
	}
	if filePath == "" {
		return l, nil
	}

	// 自动创建日志文件所在目录，避免因目录缺失导致启动失败。
	if dir := filepath.Dir(filePath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("创建日志目录 %s 失败: %w", dir, err)
		}
	}
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("打开日志文件 %s 失败: %w", filePath, err)
	}
	l.out = f
	l.closer = f
	return l, nil
}

// SetLevel 动态调整日志级别。
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Level 返回当前日志级别。
func (l *Logger) Level() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// Enabled 判断指定级别是否会被输出，可用于避免昂贵的参数构造。
func (l *Logger) Enabled(level Level) bool {
	return level >= l.Level()
}

// WithPrefix 派生一个使用新前缀的日志记录器。
// 派生记录器与父记录器共享输出目标与锁；其 Close 为空操作，
// 文件句柄始终由创建它的父记录器负责释放。
func (l *Logger) WithPrefix(prefix string) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	return &Logger{
		mu:     l.mu,
		level:  l.level,
		out:    l.out,
		prefix: prefix,
	}
}

// Close 关闭底层日志文件（若存在）。
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closer != nil {
		err := l.closer.Close()
		l.closer = nil
		return err
	}
	return nil
}

// Debugf 输出 debug 级别日志。
func (l *Logger) Debugf(format string, args ...any) { l.logf(LevelDebug, format, args...) }

// Infof 输出 info 级别日志。
func (l *Logger) Infof(format string, args ...any) { l.logf(LevelInfo, format, args...) }

// Warnf 输出 warn 级别日志。
func (l *Logger) Warnf(format string, args ...any) { l.logf(LevelWarn, format, args...) }

// Errorf 输出 error 级别日志。
func (l *Logger) Errorf(format string, args ...any) { l.logf(LevelError, format, args...) }

// logf 是内部统一的格式化输出入口，保证写入的原子性。
func (l *Logger) logf(level Level, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	// 预先格式化内容，缩短持锁时间。
	content := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s [%-5s] [%s] %s\n",
		time.Now().Format("2006-01-02 15:04:05.000"), level, l.prefix, content)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.out == nil {
		return
	}
	// 日志写入失败无法进一步处理，忽略返回的错误以保证主流程不被日志拖垮。
	_, _ = io.WriteString(l.out, line)
}
