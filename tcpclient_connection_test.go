package gos7

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestConnectContextCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	handler := NewTCPClientHandler(listener.Addr().String(), 0, 1)
	handler.IdleTimeout = 0
	defer handler.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handler.ConnectContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled dial, got %v", err)
	}
	handler.mu.Lock()
	connected := handler.conn != nil
	handler.mu.Unlock()
	if connected {
		t.Fatal("canceled dial retained a connection")
	}
}

func TestConnectHandshakeFailureCanReconnect(t *testing.T) {
	for _, failure := range []string{"iso EOF", "iso invalid reply", "pdu EOF", "pdu invalid reply"} {
		t.Run(failure, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			peerDone := make(chan error, 1)
			go func() {
				for attempt := 0; attempt < 2; attempt++ {
					conn, err := listener.Accept()
					if err != nil {
						peerDone <- err
						return
					}
					currentFailure := ""
					if attempt == 0 {
						currentFailure = failure
					}
					err = serveHandshake(conn, currentFailure)
					conn.Close()
					if err != nil {
						peerDone <- err
						return
					}
				}
				peerDone <- nil
			}()

			handler := NewTCPClientHandler(listener.Addr().String(), 0, 1)
			handler.Timeout = time.Second
			handler.IdleTimeout = 0
			defer handler.Close()
			err = handler.ConnectContext(context.Background())
			if err == nil {
				t.Fatal("failed handshake unexpectedly succeeded")
			}
			if (failure == "iso EOF" || failure == "pdu EOF") && !errors.Is(err, io.EOF) {
				t.Fatalf("handshake transport error was lost: %v", err)
			}
			handler.mu.Lock()
			connected := handler.conn != nil
			handler.mu.Unlock()
			if connected {
				t.Fatal("failed handshake retained a closed connection")
			}

			// Retry through the legacy API to verify both entry points.
			if err := handler.Connect(); err != nil {
				t.Fatalf("same handler cannot reconnect after failure: %v", err)
			}
			if handler.PDULength != 480 {
				t.Fatalf("unexpected negotiated PDU: %d", handler.PDULength)
			}
			if err := handler.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-peerDone:
				if err != nil {
					t.Fatalf("local protocol peer: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("local protocol peer did not finish")
			}
		})
	}
}

func serveHandshake(conn net.Conn, failure string) error {
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if err := readHandshakePacket(conn); err != nil {
		return err
	}
	if failure == "iso EOF" {
		return nil
	}
	isoReply := make([]byte, 22)
	isoReply[5] = 0xd0
	if failure == "iso invalid reply" {
		isoReply[5] = 0
	}
	if err := writeHandshakePacket(conn, isoReply); err != nil {
		return err
	}
	if failure == "iso invalid reply" {
		return waitHandshakeClose(conn)
	}
	if err := readHandshakePacket(conn); err != nil {
		return err
	}
	if failure == "pdu EOF" {
		return nil
	}
	pduReply := make([]byte, 27)
	binary.BigEndian.PutUint16(pduReply[25:], 480)
	if failure == "pdu invalid reply" {
		binary.BigEndian.PutUint16(pduReply[25:], 0)
	}
	if err := writeHandshakePacket(conn, pduReply); err != nil {
		return err
	}
	return waitHandshakeClose(conn)
}

func readHandshakePacket(conn net.Conn) error {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if length < 4 || length > 1024 {
		return fmt.Errorf("invalid local request length %d", length)
	}
	_, err := io.CopyN(io.Discard, conn, int64(length-4))
	return err
}

func writeHandshakePacket(conn net.Conn, packet []byte) error {
	packet[0] = 3
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	_, err := conn.Write(packet)
	return err
}

func waitHandshakeClose(conn net.Conn) error {
	var extra [1]byte
	if _, err := conn.Read(extra[:]); !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected client to close connection, got %v", err)
	}
	return nil
}
