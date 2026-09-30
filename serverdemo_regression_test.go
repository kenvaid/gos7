package gos7

import (
	"bytes"
	"testing"
	"time"
)

func TestSnap7ClockResponseVariants(t *testing.T) {
	for _, marker := range []byte{0x19, 0x20} {
		for day := 27; day <= 30; day++ {
			for _, zeroBased := range []bool{false, true} {
				if marker == 0x19 && zeroBased {
					continue
				}
				want := time.Date(2026, 9, day, 12, 13, 14, 0, time.UTC)
				c, _ := fixtureClient(func(req []byte) ([]byte, error) {
					p := make([]byte, 10)
					p[1] = marker
					if err := (&Helper{}).SetDateTimeAtChecked(p, 2, want); err != nil {
						t.Fatal(err)
					}
					if zeroBased {
						p[9]--
					}
					return fixtureUD(req, p, 0, 0, 0), nil
				})
				got, err := c.GetPLCDateTime()
				if err != nil || !got.Equal(want) {
					t.Fatalf("marker=%x zeroBased=%t day=%d: %v %v", marker, zeroBased, day, got, err)
				}
			}
		}
	}
	for _, bad := range []struct{ marker, weekday, month byte }{{0x21, 4, 9}, {0x20, 7, 9}, {0x20, 4, 0x1a}} {
		c, _ := fixtureClient(func(req []byte) ([]byte, error) {
			return fixtureUD(req, []byte{0, bad.marker, 0x26, bad.month, 0x30, 0x12, 0x13, 0x14, 0, bad.weekday}, 0, 0, 0), nil
		})
		if _, err := c.GetPLCDateTime(); err == nil {
			t.Fatalf("invalid clock accepted: %+v", bad)
		}
	}
}

func TestSnap7EmptyBlockTypes(t *testing.T) {
	calls := 0
	c, f := fixtureClient(func(req []byte) ([]byte, error) {
		calls++
		if req[30] != blockDB {
			return fixtureUD(req, nil, 0, 0, 0xd20e), nil
		}
		return fixtureUD(req, []byte{0, 1, 0x22, 5, 0, 2, 0x22, 5, 0, 3, 0x22, 5}, 0, 0, 0), nil
	})
	got, err := c.PGListBlocks()
	if err != nil || calls != 7 || len(got.DBList) != 3 || got.DBList[2] != 3 || f.closed != 0 {
		t.Fatal(got, err, calls, f.closed)
	}
	// A failure in a continuation must not silently discard an incomplete list.
	n := 0
	c, _ = fixtureClient(func(req []byte) ([]byte, error) {
		n++
		if n == 1 {
			return fixtureUD(req, []byte{0, 1, 0x22, 5}, 1, 9, 0), nil
		}
		return fixtureUD(req, nil, 0, 9, 0xd20e), nil
	})
	if _, err := c.pgBlockList(blockDB); err == nil {
		t.Fatal("continuation failure accepted")
	}
}

func TestSnap7ReadItemErrorAndPadding(t *testing.T) {
	for _, length := range []byte{0, 4} {
		for _, padding := range []byte{0, 0xa5, 0xff} {
			c, f := fixtureClient(func(req []byte) ([]byte, error) {
				return fixtureAck(req, []byte{4, 3}, []byte{0x0a, 0, 0, length, 0xff, 4, 0, 8, 0x42, padding, 0xff, 4, 0, 8, 0x43}, 0), nil
			})
			items := []S7DataItem{{Area: 0x84, WordLen: 2, DBNumber: 65535, Amount: 1, Data: []byte{0xcc}}, {Area: 0x84, WordLen: 2, DBNumber: 1, Amount: 1, Data: []byte{0}}, {Area: 0x84, WordLen: 2, DBNumber: 1, Amount: 1, Data: []byte{0}}}
			if err := c.AGReadMulti(items, 3); err != nil || items[0].Error == "" || items[0].Data[0] != 0xcc || !bytes.Equal(items[1].Data, []byte{0x42}) || items[2].Data[0] != 0x43 || f.closed != 0 {
				t.Fatal(items, err, f.closed)
			}
		}
	}
	for _, length := range []byte{1, 3, 5, 255} {
		c, _ := fixtureClient(func(req []byte) ([]byte, error) {
			return fixtureAck(req, []byte{4, 1}, []byte{0x0a, 0, 0, length}, 0), nil
		})
		if err := c.AGReadDB(1, 0, 1, []byte{0xcc}); err == nil {
			t.Fatal("invalid error header accepted")
		}
	}
}

func TestSnap7EmptyUserDataAcknowledgements(t *testing.T) {
	for _, data := range [][]byte{{0xff, 9, 0, 0}, {0x0a, 0, 0, 0}} {
		c, f := fixtureClient(func(req []byte) ([]byte, error) {
			params := []byte{0, 1, 0x12, 8, 0x12, 0x80 | req[22]&15, req[23], 0, 0, 0, 0, 0}
			return fixturePacket(7, uint16(req[11])<<8|uint16(req[12]), params, data, 0), nil
		})
		if err := c.SetPLCDateTime(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
		if err := c.SetSessionPassword("test"); err != nil {
			t.Fatal(err)
		}
		if err := c.ClearSessionPassword(); err != nil || f.closed != 0 {
			t.Fatal(err, f.closed)
		}
		if _, err := c.GetPLCDateTime(); err == nil {
			t.Fatal("empty read response accepted")
		}
	}
	for _, data := range [][]byte{{0x0a, 0, 0, 1}, {0x0a, 0, 0, 0, 1}, {0xff, 9, 0, 1, 1}, {0x05, 0, 0, 0}} {
		c, _ := fixtureClient(func(req []byte) ([]byte, error) {
			params := []byte{0, 1, 0x12, 8, 0x12, 0x80 | req[22]&15, req[23], 0, 0, 0, 0, 0}
			return fixturePacket(7, uint16(req[11])<<8|uint16(req[12]), params, data, 0), nil
		})
		if err := c.ClearSessionPassword(); err == nil {
			t.Fatalf("invalid acknowledgement accepted: %x", data)
		}
	}
	c, _ := fixtureClient(func(req []byte) ([]byte, error) { return fixtureUD(req, nil, 0, 0, 0xd241), nil })
	if err := c.ClearSessionPassword(); err == nil {
		t.Fatal("CPU rejection lost")
	}
}
