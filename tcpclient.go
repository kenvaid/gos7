package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	tcpTimeout          = 10 * time.Second
	tcpIdleTimeout      = 60 * time.Second
	tcpMaxLength        = 2084
	pduSizeRequested    = 480
	isoTCP              = 102
	isoHSize            = 7
	minPduSize          = 17
	connectionTypePG    = 1
	connectionTypeOP    = 2
	connectionTypeBasic = 3
)

type TCPClientHandler struct {
	tcpPackager
	tcpTransporter
}

// Configure Address, Timeout, IdleTimeout and Logger before concurrent use.
func NewTCPClientHandler(address string, rack, slot int) *TCPClientHandler {
	return NewTCPClientHandlerWithConnectType(address, rack, slot, connectionTypePG)
}

func NewTCPClientHandlerWithConnectType(address string, rack, slot, connectType int) *TCPClientHandler {
	h := &TCPClientHandler{}
	h.Timeout, h.IdleTimeout, h.ConnectionType = tcpTimeout, tcpIdleTimeout, connectType
	if rack < 0 || rack > 7 || slot < 0 || slot > 31 || connectType < 1 || connectType > 3 {
		h.configError = fmt.Errorf("s7: invalid rack, slot or connection type")
	}
	h.setConnectionParameters(address, 0x0100, uint16(connectType<<8|rack<<5|slot))
	return h
}

// ConnectedClient adds session lifecycle methods without extending Client and
// breaking custom implementations of the existing data-access interface.
type ConnectedClient interface {
	Client
	ClockClient
	Connect() error
	ConnectContext(context.Context) error
	Close() error
}

// TCPClient exposes the session lifecycle. Call Connect before accessing data.
func TCPClient(address string, rack, slot int) ConnectedClient {
	return NewClient(NewTCPClientHandler(address, rack, slot)).(*client)
}
func TCPClientWithConnectType(address string, rack, slot, connectType int) ConnectedClient {
	return NewClient(NewTCPClientHandlerWithConnectType(address, rack, slot, connectType)).(*client)
}

type tcpPackager struct{}
type tcpTransporter struct {
	Address              string
	Timeout, IdleTimeout time.Duration
	Logger               *log.Logger
	// exchangeGate covers whole handshakes and request/response exchanges.
	// mu protects state; Close only takes mu so it can interrupt blocked I/O.
	exchangeGate                                               chan struct{}
	mu                                                         sync.Mutex
	conn                                                       net.Conn
	ready                                                      bool
	generation                                                 uint64
	timerGeneration                                            uint64
	closeTimer                                                 *time.Timer
	lastActivity                                               time.Time
	localTSAPHigh, localTSAPLow, remoteTSAPHigh, remoteTSAPLow byte
	ConnectionType                                             int
	// Deprecated: read PDUSize during concurrent use. Configure public fields
	// before use; do not read/write these compatibility snapshots concurrently.
	LastPDUType byte
	PDULength   int
	reference   uint16
	configError error
}

func (mb *tcpTransporter) setConnectionParameters(address string, localTSAP, remoteTSAP uint16) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		if address == "" {
			mb.configError = fmt.Errorf("s7: empty address")
		}
		address = net.JoinHostPort(address, strconv.Itoa(isoTCP))
	}
	mb.Address = address
	mb.localTSAPHigh, mb.localTSAPLow = byte(localTSAP>>8), byte(localTSAP)
	mb.remoteTSAPHigh, mb.remoteTSAPLow = byte(remoteTSAP>>8), byte(remoteTSAP)
}

func (mb *tcpTransporter) NextReference() uint16 {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.reference++
	if mb.reference == 0 {
		mb.reference = 1
	}
	return mb.reference
}
func (mb *tcpTransporter) PDUSize() (int, error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	if !mb.ready || mb.conn == nil {
		return 0, fmt.Errorf("s7: connection is not established")
	}
	return mb.PDULength, nil
}

func (mb *tcpTransporter) Send(request []byte) ([]byte, error) {
	response, _, err := mb.sendPacket(request)
	return response, err
}

// SendWithSession binds validation cleanup to the session used for this reply.
// A delayed decoder cannot close a newer connection established by another caller.
func (mb *tcpTransporter) SendWithSession(request []byte) ([]byte, func(), error) {
	response, conn, err := mb.sendPacket(request)
	if err != nil {
		return nil, nil, err
	}
	return response, func() { mb.discard(conn) }, nil
}
func (mb *tcpTransporter) sendPacket(request []byte) ([]byte, net.Conn, error) {
	if _, err := parseS7(request); err != nil {
		return nil, nil, err
	}
	if err := mb.lockExchange(context.Background()); err != nil {
		return nil, nil, err
	}
	defer mb.unlockExchange()
	mb.mu.Lock()
	conn, size, ready := mb.conn, mb.PDULength, mb.ready
	if conn == nil || !ready {
		mb.mu.Unlock()
		return nil, nil, fmt.Errorf("s7: connection to %s is not established", mb.Address)
	}
	if len(request)-isoHSize > size {
		mb.mu.Unlock()
		return nil, nil, fmt.Errorf("s7: request exceeds negotiated PDU")
	}
	mb.timerGeneration++
	if mb.closeTimer != nil {
		mb.closeTimer.Stop()
		mb.closeTimer = nil
	}
	mb.mu.Unlock()
	response, err := mb.exchange(conn, request, size+isoHSize, context.Background())
	if err == nil {
		err = verifyS7(request, response)
	}
	if err != nil {
		mb.discard(conn)
		return nil, nil, err
	}
	mb.touch(conn)
	return response, conn, nil
}

// Caller holds exchangeGate; never expose a partially received frame.
func (mb *tcpTransporter) exchange(conn net.Conn, request []byte, limit int, ctx context.Context) ([]byte, error) {
	var deadline time.Time
	if mb.Timeout > 0 {
		deadline = time.Now().Add(mb.Timeout)
	}
	if d, ok := ctx.Deadline(); ok && (deadline.IsZero() || d.Before(deadline)) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	mb.logf("s7: sending % x", request)
	for remaining := request; len(remaining) > 0; {
		n, err := conn.Write(remaining)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrShortWrite
		}
		remaining = remaining[n:]
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if header[0] != 3 || header[1] != 0 || length < 7 || length > limit {
		return nil, fmt.Errorf("s7: invalid TPKT header/length")
	}
	response := make([]byte, length)
	copy(response, header)
	if _, err := io.ReadFull(conn, response[4:]); err != nil {
		return nil, err
	}
	mb.logf("s7: received % x", response)
	return response, nil
}

func (mb *tcpTransporter) Connect() error { return mb.ConnectContext(context.Background()) }

// ConnectContext cancels TCP and protocol handshakes. An established session's
// Connect is idempotent; failed attempts never publish an established session.
func (mb *tcpTransporter) ConnectContext(ctx context.Context) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = mb.lockExchange(ctx); err != nil {
		return err
	}
	defer mb.unlockExchange()
	if err = ctx.Err(); err != nil {
		return err
	}
	mb.mu.Lock()
	if mb.ready && mb.conn != nil {
		mb.mu.Unlock()
		return nil
	}
	if mb.configError != nil {
		err = mb.configError
		mb.mu.Unlock()
		return err
	}
	gen := mb.generation
	mb.mu.Unlock()
	dialer := net.Dialer{Timeout: mb.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", mb.Address)
	if err != nil {
		return err
	}
	mb.mu.Lock()
	if mb.generation != gen {
		mb.mu.Unlock()
		conn.Close()
		return fmt.Errorf("s7: connection attempt closed")
	}
	mb.conn = conn
	mb.mu.Unlock()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	defer func() {
		if err != nil {
			mb.discard(conn)
			if ctx.Err() != nil {
				err = ctx.Err()
			}
		}
	}()
	if err = mb.isoConnectOn(conn, ctx); err != nil {
		return err
	}
	var size int
	size, err = mb.negotiateOn(conn, ctx)
	if err != nil {
		return err
	}
	if !stopCancel() || ctx.Err() != nil {
		return ctx.Err()
	}
	mb.mu.Lock()
	if mb.conn != conn || mb.generation != gen {
		mb.mu.Unlock()
		return fmt.Errorf("s7: connection attempt closed")
	}
	mb.PDULength, mb.ready = size, true
	mb.LastPDUType = 0xf0
	mb.lastActivity = time.Now()
	mb.startCloseTimer()
	mb.mu.Unlock()
	return nil
}

func (mb *tcpTransporter) isoConnectOn(conn net.Conn, ctx context.Context) error {
	request := append([]byte(nil), isoConnectionRequestTelegram...)
	request[16], request[17], request[20], request[21] = mb.localTSAPHigh, mb.localTSAPLow, mb.remoteTSAPHigh, mb.remoteTSAPLow
	response, err := mb.exchange(conn, request, tcpMaxLength, ctx)
	if err != nil {
		return err
	}
	if len(response) < 11 || int(response[4])+5 != len(response) || response[5] != 0xd0 || response[10] != 0 || response[6] != request[8] || response[7] != request[9] {
		return fmt.Errorf("s7: invalid ISO connection confirm")
	}
	for offset := 11; offset < len(response); {
		if offset+2 > len(response) || offset+2+int(response[offset+1]) > len(response) {
			return fmt.Errorf("s7: invalid COTP parameters")
		}
		offset += 2 + int(response[offset+1])
	}
	return nil
}
func (mb *tcpTransporter) negotiateOn(conn net.Conn, ctx context.Context) (int, error) {
	request := append([]byte(nil), s7PDUNegogiationTelegram...)
	binary.BigEndian.PutUint16(request[11:13], mb.NextReference())
	response, err := mb.exchange(conn, request, pduSizeRequested+isoHSize, ctx)
	if err != nil {
		return 0, err
	}
	if err = verifyS7(request, response); err != nil {
		return 0, err
	}
	message, err := parseS7(response)
	if err != nil {
		return 0, err
	}
	if err = messageError(message); err != nil {
		return 0, err
	}
	if len(message.params) != 8 || len(message.data) != 0 || message.params[1] != 0 || binary.BigEndian.Uint16(message.params[2:4]) < 1 || binary.BigEndian.Uint16(message.params[4:6]) < 1 {
		return 0, fmt.Errorf("s7: invalid setup communication reply")
	}
	size := int(binary.BigEndian.Uint16(message.params[6:8]))
	if size < minNegotiatedPDU || size > pduSizeRequested {
		return 0, fmt.Errorf("s7: invalid negotiated PDU length %d", size)
	}
	return size, nil
}

func (mb *tcpTransporter) touch(conn net.Conn) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	if mb.conn == conn {
		mb.LastPDUType = 0xf0
		mb.lastActivity = time.Now()
		mb.startCloseTimer()
	}
}
func (mb *tcpTransporter) lockExchange(ctx context.Context) error {
	mb.mu.Lock()
	if mb.exchangeGate == nil {
		mb.exchangeGate = make(chan struct{}, 1)
		mb.exchangeGate <- struct{}{}
	}
	gate := mb.exchangeGate
	mb.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-gate:
		return nil
	}
}
func (mb *tcpTransporter) unlockExchange() { mb.exchangeGate <- struct{}{} }

// Caller holds mu; the timer belongs to one connection generation.
func (mb *tcpTransporter) startCloseTimer() {
	mb.timerGeneration++
	if mb.closeTimer != nil {
		mb.closeTimer.Stop()
		mb.closeTimer = nil
	}
	if mb.IdleTimeout <= 0 {
		return
	}
	conn, gen, timerGen := mb.conn, mb.generation, mb.timerGeneration
	mb.closeTimer = time.AfterFunc(mb.IdleTimeout, func() {
		mb.mu.Lock()
		defer mb.mu.Unlock()
		if mb.conn == conn && mb.generation == gen && mb.timerGeneration == timerGen {
			idle := time.Since(mb.lastActivity)
			if idle >= mb.IdleTimeout {
				_ = mb.close()
			} else {
				mb.startCloseTimer()
			}
		}
	})
}
func (mb *tcpTransporter) Close() error { mb.mu.Lock(); defer mb.mu.Unlock(); return mb.close() }
func (mb *tcpTransporter) close() error {
	mb.generation++
	mb.timerGeneration++
	if mb.closeTimer != nil {
		mb.closeTimer.Stop()
		mb.closeTimer = nil
	}
	conn := mb.conn
	mb.conn, mb.ready, mb.PDULength, mb.LastPDUType = nil, false, 0, 0
	if conn != nil {
		return conn.Close()
	}
	return nil
}
func (mb *tcpTransporter) discard(conn net.Conn) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	if mb.conn == conn {
		_ = mb.close()
	}
}
func (mb *tcpTransporter) logf(format string, v ...interface{}) {
	if mb.Logger != nil {
		mb.Logger.Printf(format, v...)
	}
}
func (mb *tcpPackager) Verify(request, response []byte) error { return verifyS7(request, response) }

func (mb *client) Connect() error { return mb.ConnectContext(context.Background()) }
func (mb *client) ConnectContext(ctx context.Context) error {
	if transport, ok := mb.transporter.(interface{ ConnectContext(context.Context) error }); ok {
		return transport.ConnectContext(ctx)
	}
	return fmt.Errorf("s7: transport does not provide connection lifecycle")
}
func (mb *client) Close() error {
	if transport, ok := mb.transporter.(interface{ Close() error }); ok {
		return transport.Close()
	}
	return fmt.Errorf("s7: transport does not provide connection lifecycle")
}
