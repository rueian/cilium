package httpredirect

import (
	"bytes"
	"io"
	"net"
	"time"
)

var RepeaterHello = []byte("HTTP/1.1 200 OK\r\n" +
	"Content-Type: text/html; charset=utf-8\r\n" +
	"Content-Length: 5\r\n" +
	"\r\n" +
	"hello")

func NewRepeater() *repeater {
	return &repeater{buf: bytes.NewReader(RepeaterHello)}
}

type repeater struct {
	buf *bytes.Reader
}

func (m *repeater) LocalAddr() net.Addr {
	return nil
}

func (m *repeater) RemoteAddr() net.Addr {
	return nil
}

func (m *repeater) SetDeadline(t time.Time) error {
	return nil
}

func (m *repeater) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *repeater) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *repeater) Write(bytes []byte) (int, error) {
	return len(bytes), nil
}

func (m *repeater) Read(buf []byte) (int, error) {
	n, err := m.buf.Read(buf)
	if err == io.EOF {
		m.buf.Seek(0, 0)
		if n == 0 {
			n, err = m.buf.Read(buf)
		}
	}
	return n, err
}

func (m *repeater) Close() error {
	return nil
}
