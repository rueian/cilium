package httpredirect

import (
	"bytes"
	"io"
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

func (m *repeater) Write(bytes []byte) (int, error) {
	return len(bytes), nil
}

func (m *repeater) Read(bytes []byte) (int, error) {
	n, err := io.ReadFull(m.buf, bytes)
	if n == 0 && err == io.EOF {
		m.buf.Seek(0, 0)
		n, err = io.ReadFull(m.buf, bytes)
	}
	return n, err
}

func (m *repeater) Close() error {
	return nil
}
