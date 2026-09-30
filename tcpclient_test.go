package gos7

import (
	"errors"
	"io"
	"net"
	"testing"
)

func TestTCPTransporter(t *testing.T) {
	h, done := localPeer(t, func(conn net.Conn) error {
		if e := fixtureHandshake(conn, 240); e != nil {
			return e
		}
		req, e := readFixture(conn)
		if e != nil {
			return e
		}
		reply, _ := autoReply(req)
		if _, e = conn.Write(reply); e != nil {
			return e
		}
		var b [1]byte
		_, e = conn.Read(b[:])
		if errors.Is(e, io.EOF) {
			return nil
		}
		return e
	})
	if e := h.Connect(); e != nil {
		t.Fatal(e)
	}
	b := []byte{0}
	if e := NewClient(h).AGReadMB(0, 1, b); e != nil || b[0] != 0x12 {
		t.Fatal(b, e)
	}
	if e := h.Close(); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestTCPConfiguration(t *testing.T) {
	for _, input := range []struct{ rack, slot, kind int }{{-1, 0, 1}, {8, 0, 1}, {0, 32, 1}, {0, 1, 0}, {0, 1, 4}} {
		h := NewTCPClientHandlerWithConnectType("127.0.0.1", input.rack, input.slot, input.kind)
		if h.Connect() == nil {
			h.Close()
			t.Fatal("invalid TSAP configuration accepted")
		}
	}
	h := NewTCPClientHandler("::1", 0, 1)
	if h.Address != "[::1]:102" {
		t.Fatal(h.Address)
	}
}
