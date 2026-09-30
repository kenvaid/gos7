package gos7

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Fixtures encode all TPKT, COTP, S7 lengths and references independently of
// production packet builders. No implicit zero-filled receive buffer is used.
func fixturePacket(kind byte, ref uint16, params, data []byte, code uint16) []byte {
	hdr := 17
	if kind == 2 || kind == 3 {
		hdr = 19
	}
	p := make([]byte, hdr+len(params)+len(data))
	copy(p, []byte{3, 0, 0, 0, 2, 0xf0, 0x80, 0x32, kind, 0, 0})
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[11:], ref)
	binary.BigEndian.PutUint16(p[13:], uint16(len(params)))
	binary.BigEndian.PutUint16(p[15:], uint16(len(data)))
	if hdr == 19 {
		binary.BigEndian.PutUint16(p[17:], code)
	}
	copy(p[hdr:], params)
	copy(p[hdr+len(params):], data)
	return p
}
func fixtureAck(req, params, data []byte, code uint16) []byte {
	return fixturePacket(3, binary.BigEndian.Uint16(req[11:]), params, data, code)
}
func fixtureUD(req, payload []byte, more, seq byte, code uint16) []byte {
	params := []byte{0, 1, 0x12, 8, 0x12, 0x80 | req[22]&15, req[23], seq, 0, more, byte(code >> 8), byte(code)}
	data := []byte{0xff, 9, byte(len(payload) >> 8), byte(len(payload))}
	data = append(data, payload...)
	return fixturePacket(7, binary.BigEndian.Uint16(req[11:]), params, data, 0)
}

type fixtureTransport struct {
	tcpPackager
	reply         func([]byte) ([]byte, error)
	calls, closed int
	size          int
}

func (f *fixtureTransport) Send(p []byte) ([]byte, error) { f.calls++; return f.reply(p) }
func (f *fixtureTransport) Close() error                  { f.closed++; return nil }
func (f *fixtureTransport) PDUSize() (int, error) {
	if f.size == 0 {
		return 240, nil
	}
	return f.size, nil
}
func fixtureClient(fn func([]byte) ([]byte, error)) (*client, *fixtureTransport) {
	f := &fixtureTransport{reply: fn}
	return NewClient(f).(*client), f
}
func autoReply(req []byte) ([]byte, error) {
	count := int(req[18])
	if req[17] == 5 {
		return fixtureAck(req, []byte{5, byte(count)}, bytes.Repeat([]byte{0xff}, count), 0), nil
	}
	var data []byte
	for i := 0; i < count; i++ {
		p := req[19+i*12:]
		word, amount := int(p[3]), int(binary.BigEndian.Uint16(p[4:]))
		size := dataSizeByte(word) * amount
		transport, length := itemTransport(word, size, amount)
		data = append(data, 0xff, transport, byte(length>>8), byte(length))
		data = append(data, bytes.Repeat([]byte{0x12}, size)...)
		if i < count-1 && size%2 == 1 {
			data = append(data, 0)
		}
	}
	return fixtureAck(req, []byte{4, byte(count)}, data, 0), nil
}
func TestResponseErrorAndMatching(t *testing.T) {
	c, f := fixtureClient(func(req []byte) ([]byte, error) { return fixtureAck(req, nil, nil, 0x8104), nil })
	err := c.AGReadMB(0, 1, make([]byte, 1))
	var s7err *S7Error
	if !errors.As(err, &s7err) || s7err.High != 0x81 || f.closed != 0 {
		t.Fatalf("global error lost: %v", err)
	}
	c, f = fixtureClient(func(req []byte) ([]byte, error) { p, _ := autoReply(req); p[12]++; return p, nil })
	if c.AGReadMB(0, 1, make([]byte, 1)) == nil || f.closed != 1 {
		t.Fatal("unmatched reply accepted")
	}
	if responseError(&ProtocolDataUnit{Data: fixturePacket(3, 1, []byte{4, 0}, nil, 0)}) != nil {
		t.Fatal("zero CPU error is non-nil")
	}
}
func TestMultiAddressAndLengths(t *testing.T) {
	for _, write := range []bool{false, true} {
		c, _ := fixtureClient(func(req []byte) ([]byte, error) {
			p := req[19:31]
			if !bytes.Equal(p[9:12], []byte{0, 3, 0x23}) {
				t.Fatalf("DBX100.3 address=%x", p[9:12])
			}
			if write && len(req) != 36 {
				t.Fatalf("final odd padding present: %d", len(req))
			}
			return autoReply(req)
		})
		items := []S7DataItem{{Area: 0x84, DBNumber: 1, WordLen: 1, Start: 100, Bit: 3, Amount: 1, Data: []byte{1}}}
		var e error
		if write {
			e = c.AGWriteMulti(items, 1)
		} else {
			e = c.AGReadMulti(items, 1)
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, word := range []int{2, 3, 4, 5, 6, 7, 8, 0x1c, 0x1d} {
		area := 0x84
		if word == 0x1c || word == 0x1d {
			area = word
		}
		c, _ := fixtureClient(autoReply)
		items := []S7DataItem{{Area: area, WordLen: word, Amount: 1, Data: make([]byte, dataSizeByte(word))}, {Area: 0x84, WordLen: 2, Amount: 1, Data: make([]byte, 1)}}
		if e := c.AGReadMulti(items, 2); e != nil {
			t.Fatalf("word %x: %v", word, e)
		}
		if e := c.AGWriteMulti(items, 2); e != nil {
			t.Fatalf("write word %x: %v", word, e)
		}
	}
}
func TestMalformedMultiNeverPublishes(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(p []byte) []byte { return p[:len(p)-1] },
		func(p []byte) []byte { p[15]++; return p },
		func(p []byte) []byte { p[20] = 2; return p },
		func(p []byte) []byte { p[22] = 0xff; return p },
		func(p []byte) []byte { p[24] = 16; return p },
		func(p []byte) []byte {
			p = append(p, 0)
			binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
			binary.BigEndian.PutUint16(p[15:], uint16(len(p)-21))
			return p
		},
	} {
		c, f := fixtureClient(func(req []byte) ([]byte, error) { p, _ := autoReply(req); return mutate(p), nil })
		b := []byte{0x77}
		if c.AGReadMB(0, 1, b) == nil || b[0] != 0x77 || f.closed != 1 {
			t.Fatal("malformed read accepted/published")
		}
	}
	c, _ := fixtureClient(func(req []byte) ([]byte, error) { return fixtureAck(req, []byte{4, 1}, []byte{5, 0, 0, 0}, 0), nil })
	items := []S7DataItem{{Area: 0x83, WordLen: 2, Amount: 1, Data: []byte{9}}}
	if c.AGReadMulti(items, 1) != nil || items[0].Error == "" || items[0].Data[0] != 9 {
		t.Fatal("item error not preserved")
	}
}
func TestValidationBeforeIO(t *testing.T) {
	good := S7DataItem{Area: 0x84, DBNumber: 1, WordLen: 2, Amount: 1, Data: []byte{0}}
	for _, change := range []func(*S7DataItem){func(i *S7DataItem) { i.Start = -1 }, func(i *S7DataItem) { i.Start = 0x200000 }, func(i *S7DataItem) { i.DBNumber = 65536 }, func(i *S7DataItem) { i.Amount = 0 }, func(i *S7DataItem) { i.Amount = int(^uint(0) >> 1) }, func(i *S7DataItem) { i.WordLen = 0 }, func(i *S7DataItem) { i.Area = 0 }, func(i *S7DataItem) { i.Data = nil }, func(i *S7DataItem) { i.Bit = 1 }} {
		i := good
		change(&i)
		c, f := fixtureClient(autoReply)
		if c.AGWriteMulti([]S7DataItem{i}, 1) == nil || f.calls != 0 {
			t.Fatal("invalid input reached transport")
		}
	}
	c, f := fixtureClient(autoReply)
	for _, n := range []int{-1, 0, 2, 21} {
		if c.AGReadMulti([]S7DataItem{good}, n) == nil {
			t.Fatalf("count %d accepted", n)
		}
	}
	if f.calls != 0 {
		t.Fatal("invalid count reached IO")
	}
	for _, size := range []int{-1, 1, 239, 65529} {
		c, f := fixtureClient(autoReply)
		f.size = size
		if c.AGReadMB(0, 1, []byte{0}) == nil || f.calls != 0 {
			t.Fatalf("PDU %d accepted", size)
		}
	}
	c, f = fixtureClient(autoReply)
	i := good
	i.Amount = 223
	i.Data = make([]byte, 223)
	if c.AGReadMulti([]S7DataItem{i}, 1) == nil || f.calls != 0 {
		t.Fatal("oversized reply budget accepted")
	}
}
func TestSingleAreaChunkingAndRawCTTM(t *testing.T) {
	for _, word := range []int{2, 0x1c, 0x1d} {
		for _, write := range []bool{false, true} {
			offset := 100
			seen := 0
			c, _ := fixtureClient(func(req []byte) ([]byte, error) {
				if len(req)-7 > 240 {
					t.Fatal("request exceeds negotiated PDU")
				}
				p := req[19:]
				address := int(p[9])<<16 | int(p[10])<<8 | int(p[11])
				expected := offset
				if word == 2 {
					expected *= 8
				}
				if address != expected {
					t.Fatalf("address %d want %d", address, expected)
				}
				count := int(binary.BigEndian.Uint16(p[4:]))
				offset += count
				seen++
				if write {
					body := req[35:]
					if body[0] != 0xab || body[1] != 0xab {
						t.Fatal("counter/timer high byte lost")
					}
				}
				return autoReply(req)
			})
			b := bytes.Repeat([]byte{0xab}, 300*dataSizeByte(word))
			var e error
			if write {
				e = c.writeArea(wordArea(word), 0, 100, 300, word, b)
			} else {
				e = c.readArea(wordArea(word), 0, 100, 300, word, b)
			}
			if e != nil || seen < 2 {
				t.Fatalf("chunks %d: %v", seen, e)
			}
		}
	}
}
func wordArea(word int) int {
	if word == 0x1c || word == 0x1d {
		return word
	}
	return 0x83
}
func TestAddressSyntax(t *testing.T) {
	for _, s := range []string{"DB1.DBB0", "DB65535.DBW40000", "DB1.DBX100.7", "IB0", "EB0", "QW2", "AW2", "OD4", "MD4", "M0.1", "I1.2", "C100", "Z100", "T100"} {
		c, _ := fixtureClient(autoReply)
		if _, e := c.Read(s, make([]byte, 4)); e != nil {
			t.Fatalf("%s: %v", s, e)
		}
	}
	for _, s := range []string{"", "DB", "DB1.DBX0", "DB1.DBX0.8", "M", "MB", "MW-1", "DB65536.DBB0", "DB1.DBD2097151", "C65536", "IB0.1", "M1.1.1", "DB1.DBB0.0"} {
		c, f := fixtureClient(autoReply)
		if _, e := c.Read(s, make([]byte, 4)); e == nil || f.calls != 0 {
			t.Fatalf("%s accepted", s)
		}
	}
}
func szlFixture(req, records []byte, width, count int, more byte) []byte {
	p := append([]byte(nil), req[29:33]...)
	p = append(p, byte(width>>8), byte(width), byte(count>>8), byte(count))
	p = append(p, records...)
	return fixtureUD(req, p, more, 7, 0)
}
func TestSZLFragmentAndOrderCode(t *testing.T) {
	n := 0
	c, _ := fixtureClient(func(req []byte) ([]byte, error) {
		n++
		if n == 1 {
			return szlFixture(req, []byte{1, 2, 3}, 3, 2, 1), nil
		}
		if req[24] != 7 {
			t.Fatal("sequence not continued")
		}
		return fixtureUD(req, []byte{4, 5, 6}, 0, 7, 0), nil
	})
	s, size, e := c.readSzl(0x11, 0)
	if e != nil || size != 6 || s.Header.LengthHeader != 3 || !bytes.Equal(s.Data, []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("SZL %v %d: %v", s, size, e)
	}
	c, _ = fixtureClient(func(req []byte) ([]byte, error) {
		if binary.BigEndian.Uint16(req[29:]) != 0x11 {
			t.Fatal("order-code SZL ID")
		}
		p := make([]byte, 56)
		binary.BigEndian.PutUint16(p, 7)
		copy(p[25:], []byte{1, 2, 3})
		binary.BigEndian.PutUint16(p[28:], 1)
		copy(p[30:50], "6ES7 TEST MODULE")
		return szlFixture(req, p, 28, 2, 0), nil
	})
	info, e := c.GetOrderCode()
	if e != nil || info.Code != "6ES7 TEST MODULE" || info.V3 != 3 {
		t.Fatalf("%v %v", info, e)
	}
}
func TestManagementRejectsTruncatedData(t *testing.T) {
	for _, method := range []func(*client) error{func(c *client) error { _, e := c.GetAgBlockInfo(65, 1); return e }, func(c *client) error { _, e := c.GetOrderCode(); return e }, func(c *client) error { _, e := c.GetCPUInfo(); return e }, func(c *client) error { _, e := c.GetCPInfo(); return e }, func(c *client) error { _, e := c.GetProtection(); return e }, func(c *client) error { _, e := c.PLCGetStatus(); return e }, func(c *client) error { _, e := c.GetPLCDateTime(); return e }, func(c *client) error { _, e := c.PGListBlocks(); return e }} {
		c, _ := fixtureClient(func(req []byte) ([]byte, error) {
			if req[22]&15 == 4 && req[23] == 1 {
				return szlFixture(req, []byte{0}, 1, 1, 0), nil
			}
			return fixtureUD(req, []byte{0}, 0, 1, 0), nil
		})
		if method(c) == nil {
			t.Fatal("truncated management data accepted")
		}
	}
}
func TestClockProtectionCPStatusAndBlockInfo(t *testing.T) {
	dt := time.Date(2026, 9, 29, 12, 13, 14, 987000000, time.UTC)
	c, _ := fixtureClient(func(req []byte) ([]byte, error) {
		if req[23] == 2 {
			if len(req) != 39 || req[31] != 0x26 || req[38]&15 != 3 {
				t.Fatalf("SET clock packet %x", req)
			}
			return fixtureUD(req, nil, 0, 1, 0), nil
		}
		p := make([]byte, 10)
		p[1] = 0x19
		h := Helper{}
		_ = h.SetDateTimeAtChecked(p, 2, dt)
		return fixtureUD(req, p, 0, 1, 0), nil
	})
	if e := c.SetPLCDateTime(dt); e != nil {
		t.Fatal(e)
	}
	got, e := c.GetPLCDateTime()
	if e != nil || !got.Equal(dt) {
		t.Fatalf("clock %v %v", got, e)
	}
	c, _ = fixtureClient(func(req []byte) ([]byte, error) {
		id := binary.BigEndian.Uint16(req[29:])
		p := make([]byte, 14)
		switch id {
		case 0x232:
			for i := 0; i < 5; i++ {
				binary.BigEndian.PutUint16(p[2+i*2:], uint16(i+1))
			}
		case 0x131:
			if binary.BigEndian.Uint16(req[31:]) != 1 {
				t.Fatal("CP index")
			}
			binary.BigEndian.PutUint16(p[2:], 480)
			binary.BigEndian.PutUint16(p[4:], 8)
			binary.BigEndian.PutUint32(p[6:], 187500)
			binary.BigEndian.PutUint32(p[10:], 12000000)
		case 0x424:
			p[3] = 8
		}
		return szlFixture(req, p, 14, 1, 0), nil
	})
	pr, e := c.GetProtection()
	if e != nil || pr.AnlSch != 5 || pr.SchSchal != 1 {
		t.Fatalf("protection %v %v", pr, e)
	}
	cp, e := c.GetCPInfo()
	if e != nil || cp.MaxMpiRate != 187500 || cp.MaxBusRate != 12000000 {
		t.Fatalf("CP %v %v", cp, e)
	}
	status, e := c.PLCGetStatus()
	if e != nil || status != 8 {
		t.Fatal(status, e)
	}
	c, _ = fixtureClient(func(req []byte) ([]byte, error) {
		if string(req[31:36]) != "65535" {
			t.Fatal("block number encoding")
		}
		p := make([]byte, 78)
		p[11] = 65
		binary.BigEndian.PutUint16(p[12:], 65535)
		binary.BigEndian.PutUint16(p[40:], 512)
		return fixtureUD(req, p, 0, 0, 0), nil
	})
	bi, e := c.GetAgBlockInfo(65, 65535)
	if e != nil || bi.MC7Size != 512 || bi.BlkNumber != 65535 {
		t.Fatal(bi, e)
	}
}
func TestDirectoryAndSecurityControl(t *testing.T) {
	types := []byte{}
	c, _ := fixtureClient(func(req []byte) ([]byte, error) {
		types = append(types, req[30])
		return fixtureUD(req, []byte{0, 2, 0, 0}, 0, 0, 0), nil
	})
	list, e := c.PGListBlocks()
	if e != nil || len(types) != 7 || len(list.OBList) != 1 || list.OBList[0] != 2 {
		t.Fatal(types, list, e)
	}
	seen := map[byte]bool{}
	for _, kind := range types {
		if seen[kind] {
			t.Fatal("duplicate block type")
		}
		seen[kind] = true
	}
	calls := 0
	c, _ = fixtureClient(func(req []byte) ([]byte, error) { calls++; return fixtureUD(req, nil, 0, 0, 0x8104), nil })
	if _, e = c.PGListBlocks(); e == nil || calls != 1 {
		t.Fatal("directory error overwritten")
	}
	n := 0
	c, _ = fixtureClient(func(req []byte) ([]byte, error) {
		n++
		if n == 1 {
			return fixtureUD(req, []byte{0, 1, 0, 0}, 1, 9, 0), nil
		}
		if req[24] != 9 {
			t.Fatal("directory sequence")
		}
		return fixtureUD(req, []byte{0, 2, 0, 0}, 0, 9, 0), nil
	})
	b, e := c.pgBlockList(65)
	if e != nil || len(b) != 2 {
		t.Fatal(b, e)
	}
	c, f := fixtureClient(func(req []byte) ([]byte, error) { return fixtureUD(req, nil, 0, 0, 0), nil })
	if e = c.SetSessionPassword("123456789"); e == nil || f.calls != 0 {
		t.Fatal("overlong password accepted")
	}
	if e = c.SetSessionPassword("ABC"); e != nil {
		t.Fatal(e)
	}
	if e = c.ClearSessionPassword(); e != nil {
		t.Fatal(e)
	}
	c, _ = fixtureClient(func(req []byte) ([]byte, error) { return fixtureAck(req, []byte{req[17], 0}, nil, 0), nil })
	for _, m := range []func() error{c.PLCHotStart, c.PLCColdStart, c.PLCStop} {
		if e = m(); e != nil {
			t.Fatal(e)
		}
	}
}
func readFixture(conn net.Conn) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(conn, h[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(h[2:]))
	if n < 4 || n > 65535 {
		return nil, fmt.Errorf("bad fixture length")
	}
	p := make([]byte, n)
	copy(p, h[:])
	_, e := io.ReadFull(conn, p[4:])
	return p, e
}
func fixtureHandshake(conn net.Conn, size int) error {
	req, e := readFixture(conn)
	if e != nil {
		return e
	}
	confirm := []byte{3, 0, 0, 11, 6, 0xd0, req[8], req[9], 0, 1, 0}
	if _, e = conn.Write(confirm); e != nil {
		return e
	}
	req, e = readFixture(conn)
	if e != nil {
		return e
	}
	_, e = conn.Write(fixtureAck(req, []byte{0xf0, 0, 0, 1, 0, 1, byte(size >> 8), byte(size)}, nil, 0))
	return e
}
func localPeer(t *testing.T, serve func(net.Conn) error) (*TCPClientHandler, <-chan error) {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		done <- serve(conn)
	}()
	h := NewTCPClientHandler(ln.Addr().String(), 0, 1)
	h.Timeout = time.Second
	h.IdleTimeout = 0
	t.Cleanup(func() { h.Close(); ln.Close() })
	return h, done
}
func TestConcurrentConnectAndReadWrite(t *testing.T) {
	h, done := localPeer(t, func(conn net.Conn) error {
		if e := fixtureHandshake(conn, 480); e != nil {
			return e
		}
		for n := 0; n < 64; n++ {
			req, e := readFixture(conn)
			if e != nil {
				return e
			}
			reply, e := autoReply(req)
			if e != nil {
				return e
			}
			if _, e = conn.Write(reply); e != nil {
				return e
			}
		}
		return nil
	})
	if e := h.Connect(); e != nil {
		t.Fatal(e)
	}
	c := NewClient(h)
	var wg sync.WaitGroup
	errs := make(chan error, 128)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if e := h.Connect(); e != nil {
				errs <- e
				return
			}
			b := make([]byte, 2)
			var e error
			if i%2 == 0 {
				e = c.AGReadMB(i, 2, b)
			} else {
				e = c.AGWriteMB(i, 2, b)
			}
			if e != nil {
				errs <- e
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestTimeoutDropsSessionAndCloseInterrupts(t *testing.T) {
	for _, closeIO := range []bool{false, true} {
		h, done := localPeer(t, func(conn net.Conn) error {
			if e := fixtureHandshake(conn, 240); e != nil {
				return e
			}
			if _, e := readFixture(conn); e != nil {
				return e
			}
			var b [1]byte
			_, e := conn.Read(b[:])
			if errors.Is(e, io.EOF) {
				return nil
			}
			return e
		})
		h.Timeout = 100 * time.Millisecond
		if e := h.Connect(); e != nil {
			t.Fatal(e)
		}
		result := make(chan error, 1)
		go func() { result <- NewClient(h).AGReadMB(0, 1, []byte{0}) }()
		if closeIO {
			time.Sleep(20 * time.Millisecond)
			h.Close()
		}
		select {
		case e := <-result:
			if e == nil {
				t.Fatal("blocked IO returned success")
			}
		case <-time.After(time.Second):
			t.Fatal("IO not interrupted")
		}
		if _, e := h.PDUSize(); e == nil {
			t.Fatal("faulted session retained")
		}
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
}
func TestConnectContextCancelsHandshakeAndQueuedConnect(t *testing.T) {
	h, done := localPeer(t, func(conn net.Conn) error {
		if _, e := readFixture(conn); e != nil {
			return e
		}
		var b [1]byte
		_, e := conn.Read(b[:])
		if errors.Is(e, io.EOF) {
			return nil
		}
		return e
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if e := h.ConnectContext(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	h = &TCPClientHandler{}
	if e := h.lockExchange(context.Background()); e != nil {
		t.Fatal(e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e := h.ConnectContext(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	h.unlockExchange()
}
func TestIdleTimeoutAndActiveExchange(t *testing.T) {
	h, done := localPeer(t, func(conn net.Conn) error {
		if e := fixtureHandshake(conn, 240); e != nil {
			return e
		}
		req, e := readFixture(conn)
		if e != nil {
			return e
		}
		time.Sleep(90 * time.Millisecond)
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
	h.IdleTimeout = 50 * time.Millisecond
	if e := h.Connect(); e != nil {
		t.Fatal(e)
	}
	if e := NewClient(h).AGReadMB(0, 1, []byte{0}); e != nil {
		t.Fatal("idle timer interrupted active IO", e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if _, e := h.PDUSize(); e == nil {
		t.Fatal("idle session not closed")
	}
}
func FuzzProtocolParsers(f *testing.F) {
	f.Add([]byte{})
	f.Add(fixturePacket(3, 1, []byte{4, 1}, []byte{0xff, 4, 0, 8, 1}, 0))
	f.Fuzz(func(t *testing.T, p []byte) {
		_, _ = parseS7(p)
		_, _, _ = userDataPayload(p)
		_ = responseError(&ProtocolDataUnit{Data: p})
	})
}

func TestWriteTransportGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		word, area int
		transport  byte
		length     int
		value      []byte
	}{
		{1, 0x84, 3, 1, []byte{1}}, {2, 0x84, 4, 8, []byte{0x42}},
		{3, 0x84, 9, 1, []byte{'A'}}, {4, 0x84, 4, 16, []byte{0x12, 0x34}},
		{5, 0x84, 5, 16, []byte{0xff, 0xff}}, {6, 0x84, 4, 32, []byte{1, 2, 3, 4}},
		{7, 0x84, 5, 32, []byte{1, 2, 3, 4}}, {8, 0x84, 7, 4, []byte{0x3f, 0x80, 0, 0}},
		{0x1c, 0x1c, 9, 2, []byte{0x01, 0x23}}, {0x1d, 0x1d, 9, 2, []byte{0x31, 0x23}},
	} {
		c, _ := fixtureClient(func(req []byte) ([]byte, error) {
			if req[32] != tc.transport || int(binary.BigEndian.Uint16(req[33:35])) != tc.length || !bytes.Equal(req[35:], tc.value) {
				t.Fatalf("word %x wire payload %x", tc.word, req[31:])
			}
			return fixtureAck(req, []byte{5, 1}, []byte{0xff}, 0), nil
		})
		items := []S7DataItem{{Area: tc.area, WordLen: tc.word, Start: 10, Amount: 1, Data: tc.value}}
		if e := c.AGWriteMulti(items, 1); e != nil {
			t.Fatal(e)
		}
	}
	for _, timer := range []bool{false, true} {
		c, _ := fixtureClient(func(req []byte) ([]byte, error) {
			return fixtureAck(req, []byte{4, 1}, []byte{0xff, 9, 0, 2, 0x12, 0x34}, 0), nil
		})
		b := make([]byte, 2)
		var e error
		if timer {
			e = c.AGReadTM(10, 1, b)
		} else {
			e = c.AGReadCT(10, 1, b)
		}
		if e != nil || !bytes.Equal(b, []byte{0x12, 0x34}) {
			t.Fatal(b, e)
		}
	}
}
func TestProtocolIdentityMismatch(t *testing.T) {
	for _, change := range []func([]byte){
		func(p []byte) { p[0] = 2 }, func(p []byte) { p[1] = 1 }, func(p []byte) { p[5] = 0xd0 }, func(p []byte) { p[6] = 0 }, func(p []byte) { p[7] = 0 }, func(p []byte) { p[8] = 1 }, func(p []byte) { p[9] = 1 }, func(p []byte) { p[11]++ }, func(p []byte) { p[19] = 5 },
	} {
		c, f := fixtureClient(func(req []byte) ([]byte, error) {
			p := fixtureAck(req, []byte{4, 1}, []byte{0xff, 4, 0, 8, 0x42}, 0)
			change(p)
			return p, nil
		})
		if c.AGReadMB(0, 1, []byte{0}) == nil || f.closed != 1 {
			t.Fatal("invalid response identity retained")
		}
	}
}
func TestNegotiatedPDUBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 239, 240, 480, 481} {
		h, done := localPeer(t, func(conn net.Conn) error { return fixtureHandshake(conn, size) })
		e := h.Connect()
		if (e == nil) != (size == 240 || size == 480) {
			t.Fatalf("PDU %d: %v", size, e)
		}
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
}

type noPDUTransport struct {
	tcpPackager
	reply func([]byte) ([]byte, error)
}

func (f *noPDUTransport) Send(req []byte) ([]byte, error) { return f.reply(req) }
func TestGenericTransportAndClockError(t *testing.T) {
	f := &noPDUTransport{reply: autoReply}
	c := NewClient2(f, f)
	if e := c.AGReadMB(0, 1, []byte{0}); e != nil {
		t.Fatal(e)
	}
	clock := c.(ClockClient)
	sentinel := errors.New("transport unavailable")
	f.reply = func([]byte) ([]byte, error) { return nil, sentinel }
	if _, e := clock.GetPLCDateTime(); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	if _, e := c.PGClockWrite(); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	if e := c.PGClockRead(time.Now()); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	if e := c.(ConnectedClient).Connect(); e == nil {
		t.Fatal("unsupported custom lifecycle succeeded")
	}
}

func TestTransportLengthFieldCannotWrap(t *testing.T) {
	c, f := fixtureClient(autoReply)
	f.size = 65528
	item := S7DataItem{Area: 0x83, WordLen: 2, Amount: 8192, Data: make([]byte, 8192)}
	if c.AGWriteMulti([]S7DataItem{item}, 1) == nil || f.calls != 0 {
		t.Fatal("16-bit BIT length overflow accepted")
	}
	if e := c.AGReadMB(0, 9000, make([]byte, 9000)); e != nil || f.calls != 2 {
		t.Fatal("large custom PDU was not safely chunked", e, f.calls)
	}
}

func TestCPUInfoRecordIdentity(t *testing.T) {
	c, _ := fixtureClient(func(req []byte) ([]byte, error) {
		var p []byte
		for _, entry := range []struct {
			id   uint16
			text string
		}{{7, "CPU TYPE"}, {5, "SERIAL"}, {1, "AS NAME"}, {4, "COPYRIGHT"}, {2, "MODULE NAME"}} {
			record := make([]byte, 34)
			binary.BigEndian.PutUint16(record, entry.id)
			copy(record[2:], entry.text)
			p = append(p, record...)
		}
		return szlFixture(req, p, 34, 5, 0), nil
	})
	info, e := c.GetCPUInfo()
	if e != nil || info.ModuleTypeName != "CPU TYPE" || info.SerialNumber != "SERIAL" || info.ASName != "AS NAME" || info.Copyright != "COPYRIGHT" || info.ModuleName != "MODULE NAME" {
		t.Fatal(info, e)
	}
}

func TestFaultedSessionRequiresFreshHandshake(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			conn, e := ln.Accept()
			if e != nil {
				done <- e
				return
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if e = fixtureHandshake(conn, 240); e != nil {
				conn.Close()
				done <- e
				return
			}
			req, e := readFixture(conn)
			if e != nil {
				conn.Close()
				done <- e
				return
			}
			if attempt == 0 {
				var b [1]byte
				_, e = conn.Read(b[:])
				if !errors.Is(e, io.EOF) {
					conn.Close()
					done <- fmt.Errorf("faulted connection retained: %v", e)
					return
				}
			} else {
				p := fixtureAck(req, []byte{4, 1}, []byte{0xff, 4, 0, 8, 0x42}, 0)
				_, e = conn.Write(p)
				if e != nil {
					conn.Close()
					done <- e
					return
				}
			}
			conn.Close()
		}
		done <- nil
	}()
	h := NewTCPClientHandler(ln.Addr().String(), 0, 1)
	h.Timeout = 100 * time.Millisecond
	h.IdleTimeout = 0
	defer h.Close()
	c := NewClient(h)
	if e = h.Connect(); e != nil {
		t.Fatal(e)
	}
	if e = c.AGReadMB(0, 1, []byte{0}); e == nil {
		t.Fatal("timeout returned success")
	}
	if e = c.AGReadMB(1, 1, []byte{0}); e == nil {
		t.Fatal("second job reused faulted connection")
	}
	if e = h.Connect(); e != nil {
		t.Fatal(e)
	}
	b := []byte{0}
	if e = c.AGReadMB(1, 1, b); e != nil || b[0] != 0x42 {
		t.Fatal(b, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestDelayedValidationCannotCloseNewSession(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			conn, e := ln.Accept()
			if e != nil {
				done <- e
				return
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if e = fixtureHandshake(conn, 240); e != nil {
				conn.Close()
				done <- e
				return
			}
			req, e := readFixture(conn)
			if e != nil {
				conn.Close()
				done <- e
				return
			}
			p := fixtureAck(req, []byte{4, 1}, []byte{0xff, 4, 0, 8, 0x42}, 0)
			_, e = conn.Write(p)
			conn.Close()
			if e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	h := NewTCPClientHandler(ln.Addr().String(), 0, 1)
	h.IdleTimeout = 0
	h.Timeout = time.Second
	defer h.Close()
	if e = h.Connect(); e != nil {
		t.Fatal(e)
	}
	request := fixturePacket(1, h.NextReference(), []byte{4, 1, 0x12, 10, 0x10, 2, 0, 1, 0, 0, 0x83, 0, 0, 0}, nil, 0)
	_, invalidate, e := h.SendWithSession(request)
	if e != nil {
		t.Fatal(e)
	}
	h.Close()
	if e = h.Connect(); e != nil {
		t.Fatal(e)
	}
	invalidate()
	if e = NewClient(h).AGReadMB(0, 1, []byte{0}); e != nil {
		t.Fatal("old reply closed new session", e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
