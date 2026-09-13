package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// 加密帧格式：4 字节大端明文长度 + 12 字节随机 nonce + AES-GCM 密文（含 16 字节认证标签）。
// 加密对上层透明：控制报文（JSON 帧）作为普通字节流经 SecureConn 加解密，
// 上层收发逻辑无需感知加密的存在。SecureConn 仅用于控制连接；
// 承载业务数据的工作连接不加密，以避免数据阶段的开销。
const (
	// secureNonceSize 是 GCM 推荐 nonce 长度。
	secureNonceSize = 12
	// secureTagSize 是 GCM 认证标签长度。
	secureTagSize = 16
	// secureHeaderSize 是加密帧长度前缀的字节数。
	secureHeaderSize = 4
	// maxSecureChunk 是单个加密帧的明文上限，同时约束对端可触发的内存分配。
	maxSecureChunk = 32 * 1024
)

// DeriveKey 从接入令牌派生 32 字节 AES-256 密钥。
// 混入固定域盐，避免同一令牌在不同协议/版本间被复用为相同密钥。
func DeriveKey(token string) []byte {
	sum := sha256.Sum256([]byte("netunnel/token/v1\x00" + token))
	return sum[:]
}

// SecureConn 在底层连接之上提供 AES-GCM 记录加密，并透明实现 net.Conn。
//
// Write 把数据切分为不超过 maxSecureChunk 的明文块，逐块加密成帧写入；
// Read 逐帧解密并返回解密后的字节流。每帧 nonce 随机生成，在 2^32 帧
// 量级下碰撞概率可忽略。解密失败说明令牌不一致或数据被篡改。
type SecureConn struct {
	conn net.Conn
	aead cipher.AEAD

	// rbuf 保存已解密但尚未被取走的字节，屏蔽帧边界对上层的影响。
	rbuf []byte
}

// NewSecureConn 使用令牌派生的密钥包装连接，返回的连接可直接替换原连接使用。
func NewSecureConn(conn net.Conn, token string) (*SecureConn, error) {
	block, err := aes.NewCipher(DeriveKey(token))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecureConn{conn: conn, aead: aead}, nil
}

// Read 读取一帧密文、解密并填充 p，返回解密字节数。
func (c *SecureConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// 优先消费已解密但未取完的缓冲，让 io.ReadFull 等调用无需感知帧边界。
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}

	var header [secureHeaderSize]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxSecureChunk {
		return 0, errors.New("protocol: 非法密文帧长度")
	}

	frame := make([]byte, secureNonceSize+int(length)+secureTagSize)
	if _, err := io.ReadFull(c.conn, frame); err != nil {
		return 0, err
	}
	plain, err := c.aead.Open(nil, frame[:secureNonceSize], frame[secureNonceSize:], nil)
	if err != nil {
		return 0, errors.New("protocol: 解密失败（令牌不一致或数据被篡改）")
	}

	n := copy(p, plain)
	c.rbuf = plain[n:]
	return n, nil
}

// Write 把 p 切块加密后逐帧写入底层连接。
func (c *SecureConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxSecureChunk {
			chunk = chunk[:maxSecureChunk]
		}
		if err := c.writeFrame(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// writeFrame 把单个明文块加密为一帧并写入底层连接。
func (c *SecureConn) writeFrame(plain []byte) error {
	nonce := make([]byte, secureNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := c.aead.Seal(nil, nonce, plain, nil)

	buf := make([]byte, secureHeaderSize+secureNonceSize+len(sealed))
	binary.BigEndian.PutUint32(buf[:secureHeaderSize], uint32(len(plain)))
	copy(buf[secureHeaderSize:], nonce)
	copy(buf[secureHeaderSize+secureNonceSize:], sealed)

	if _, err := c.conn.Write(buf); err != nil {
		return err
	}
	return nil
}

// Close 关闭底层连接。
func (c *SecureConn) Close() error { return c.conn.Close() }

// LocalAddr 返回本地地址。
func (c *SecureConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr 返回远端地址。
func (c *SecureConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline 设置读写截止时间。
func (c *SecureConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// SetReadDeadline 设置读截止时间。
func (c *SecureConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// SetWriteDeadline 设置写截止时间。
func (c *SecureConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// CloseWrite 透传底层半关闭能力，保留 HTTP、Redis 等依赖 EOF 语义的协议。
func (c *SecureConn) CloseWrite() error {
	if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.conn.Close()
}

// CloseRead 透传底层读关闭能力。
func (c *SecureConn) CloseRead() error {
	if cr, ok := c.conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return c.conn.Close()
}
