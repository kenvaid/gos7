package gos7

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestHelperProtocolBoundaries(t *testing.T) {
	h := Helper{}
	b := make([]byte, 20)
	if e := h.SetWStringAtChecked(b, 2, 7, "中文A"); e != nil {
		t.Fatal(e)
	}
	if binary.BigEndian.Uint16(b[4:]) != 3 || h.GetWStringAt(b, 2) != "中文A" {
		t.Fatal("WSTRING character count")
	}
	before := append([]byte(nil), b...)
	if h.SetWStringAtChecked(b, 2, 7, "😀") == nil || !bytes.Equal(before, b) {
		t.Fatal("non UCS-2 value accepted")
	}
	h.SetWStringAt(b, 2, 1, "中文")
	if h.GetWStringAt(b, 2) != "中" {
		t.Fatal("WSTRING truncation")
	}
	for n := 0; n <= 999; n++ {
		raw, e := h.ToCounterChecked(n)
		if e != nil || h.GetCounter(raw) != n {
			t.Fatal("counter", n, raw, e)
		}
	}
	if h.ToCounter(123) != 0x0123 || h.GetCounter(0x0123) != 123 {
		t.Fatal("BCD order")
	}
	for _, raw := range []uint16{0xa, 0x1000, 0xa00} {
		if _, e := h.GetCounterChecked(raw); e == nil {
			t.Fatal("invalid BCD accepted")
		}
	}
	b = []byte("abcdef")
	h.SetCharsAt(b, 2, "XY")
	if string(b) != "abXYef" {
		t.Fatal("chars copied incorrectly")
	}
	b = make([]byte, 20)
	binary.BigEndian.PutUint16(b[2:], 65535)
	if v := h.GetDateAt(b, 2); !v.Equal(dateEpoch.AddDate(0, 0, 65535)) {
		t.Fatal("DATE signed")
	}
	if e := h.SetDateAtChecked(b, 2, dateEpoch.AddDate(0, 0, 65535)); e != nil {
		t.Fatal(e)
	}
	dt := time.Date(2026, 9, 29, 23, 59, 59, 987654321, time.UTC)
	h.SetTODAt(b, 2, dt)
	if n := binary.BigEndian.Uint32(b[2:]); n != 86399987 {
		t.Fatal("TOD ms", n)
	}
	if v := h.GetTODAt(b, 2); v.Nanosecond() != 987000000 || v.Hour() != 23 {
		t.Fatal("TOD offset", v)
	}
	h.SetLTODAt(b, 2, dt)
	if v := h.GetLTODAt(b, 2); v.Nanosecond() != 987654321 {
		t.Fatal("LTOD ns", v)
	}
	if e := h.SetDateTimeAtChecked(b, 2, dt); e != nil {
		t.Fatal(e)
	}
	if b[9]&15 != 3 {
		t.Fatal("DT weekday")
	}
	v, e := h.GetDateTimeAtChecked(b, 2)
	if e != nil || !v.Equal(dt.Truncate(time.Millisecond)) {
		t.Fatal(v, e)
	}
	b[3] = 0x19
	if _, e = h.GetDateTimeAtChecked(b, 2); e == nil {
		t.Fatal("invalid month accepted")
	}
	if e = h.SetDTLAtChecked(b, 2, dt); e != nil {
		t.Fatal(e)
	}
	v, e = h.GetDTLAtChecked(b, 2)
	if e != nil || !v.Equal(dt) || b[6] != 3 {
		t.Fatal(v, e)
	}
	for _, ms := range []int{0, 9990, 99900, 999000, 9990000} {
		if e = h.SetS5TimeAtChecked(b, 2, time.Duration(ms)*time.Millisecond); e != nil {
			t.Fatal(e)
		}
		if v := h.GetS5TimeAt(b, 2); v != time.Duration(ms)*time.Millisecond {
			t.Fatal("S5TIME endpoint", ms, v)
		}
	}
	if h.SetS5TimeAtChecked(b, 2, -time.Millisecond) == nil || h.SetDateTimeAtChecked(b, 2, time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC)) == nil {
		t.Fatal("range check missing")
	}
}
func TestHelperBoundsAndAtomicWrites(t *testing.T) {
	h := Helper{}
	for _, p := range []int{-1, 0, 1, 99} {
		b := []byte{0x77}
		before := append([]byte(nil), b...)
		h.SetDateTimeAt(b, p, time.Now())
		h.SetDTLAt(b, p, time.Now())
		h.SetStringAt(b, p, 10, "abc")
		h.SetWStringAt(b, p, 10, "中文")
		h.SetCharsAt(b, p, "abc")
		h.SetValueAt(b, p, uint32(123))
		h.SetS5TimeAt(b, p, time.Second)
		if !bytes.Equal(b, before) {
			t.Fatal("partial invalid write")
		}
		_ = h.GetDateTimeAt(b, p)
		_ = h.GetDTLAt(b, p)
		_ = h.GetTODAt(b, p)
		_ = h.GetLTODAt(b, p)
		_ = h.GetStringAt(b, p)
		_ = h.GetWStringAt(b, p)
		_ = h.GetCharsAt(b, p, 4)
		_ = h.GetS5TimeAt(b, p)
	}
	var out uint32 = 99
	if h.GetValueAtChecked([]byte{1}, 0, &out) == nil || out != 99 {
		t.Fatal("invalid read changed output")
	}
}
func FuzzHelpers(f *testing.F) {
	f.Add([]byte{}, 0)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, 1)
	f.Fuzz(func(t *testing.T, b []byte, p int) {
		h := Helper{}
		_ = h.GetDateTimeAt(b, p)
		_ = h.GetDateAt(b, p)
		_ = h.GetTODAt(b, p)
		_ = h.GetLTODAt(b, p)
		_ = h.GetLDTAt(b, p)
		_ = h.GetDTLAt(b, p)
		_ = h.GetS5TimeAt(b, p)
		_ = h.GetStringAt(b, p)
		_ = h.GetWStringAt(b, p)
	})
}
