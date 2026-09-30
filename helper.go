package gos7

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"time"
	"unicode/utf8"
)

// Helper encodes Siemens values in big-endian wire order. The legacy methods
// cannot report errors; invalid inputs leave buffers unchanged or return zero.
// Use the Checked variants when accepting external data.
type Helper struct{}

func span(b []byte, p, n int) error {
	if p < 0 || n < 0 || p > len(b) || n > len(b)-p {
		return fmt.Errorf("s7: buffer range out of bounds")
	}
	return nil
}
func (h *Helper) SetValueAtChecked(b []byte, p int, v interface{}) error {
	var out bytes.Buffer
	if e := binary.Write(&out, binary.BigEndian, v); e != nil {
		return e
	}
	if e := span(b, p, out.Len()); e != nil {
		return e
	}
	copy(b[p:], out.Bytes())
	return nil
}
func (h *Helper) GetValueAtChecked(b []byte, p int, v interface{}) error {
	n := binary.Size(v)
	if n < 0 {
		return fmt.Errorf("s7: unsupported value type")
	}
	if e := span(b, p, n); e != nil {
		return e
	}
	return binary.Read(bytes.NewReader(b[p:p+n]), binary.BigEndian, v)
}
func (h *Helper) SetValueAt(b []byte, p int, v interface{}) { _ = h.SetValueAtChecked(b, p, v) }
func (h *Helper) GetValueAt(b []byte, p int, v interface{}) { _ = h.GetValueAtChecked(b, p, v) }
func (h *Helper) GetRealAt(b []byte, p int) float32 {
	var v uint32
	h.GetValueAt(b, p, &v)
	return math.Float32frombits(v)
}
func (h *Helper) SetRealAt(b []byte, p int, v float32) { h.SetValueAt(b, p, math.Float32bits(v)) }
func (h *Helper) GetLRealAt(b []byte, p int) float64 {
	var v uint64
	h.GetValueAt(b, p, &v)
	return math.Float64frombits(v)
}
func (h *Helper) SetLRealAt(b []byte, p int, v float64) { h.SetValueAt(b, p, math.Float64bits(v)) }
func decodeBcd(b byte) int                              { return int(b>>4)*10 + int(b&15) }
func encodeBcd(v int) byte                              { return byte(v/10<<4 | v%10) }
func validBCD(b byte) bool                              { return b>>4 <= 9 && b&15 <= 9 }
func civil(y int, m time.Month, d, hh, mm, ss, ns int) (time.Time, error) {
	v := time.Date(y, m, d, hh, mm, ss, ns, time.UTC)
	if v.Year() != y || v.Month() != m || v.Day() != d || hh < 0 || hh > 23 || mm < 0 || mm > 59 || ss < 0 || ss > 59 || ns < 0 || ns >= 1e9 {
		return time.Time{}, fmt.Errorf("s7: invalid date/time")
	}
	return v, nil
}
func (h *Helper) GetDateTimeAtChecked(b []byte, p int) (time.Time, error) {
	if e := span(b, p, 8); e != nil {
		return time.Time{}, e
	}
	b = b[p : p+8]
	for _, x := range b[:7] {
		if !validBCD(x) {
			return time.Time{}, fmt.Errorf("s7: invalid BCD")
		}
	}
	if b[7]>>4 > 9 || b[7]&15 < 1 || b[7]&15 > 7 {
		return time.Time{}, fmt.Errorf("s7: invalid milliseconds/weekday")
	}
	y := decodeBcd(b[0])
	if y < 90 {
		y += 2000
	} else {
		y += 1900
	}
	v, e := civil(y, time.Month(decodeBcd(b[1])), decodeBcd(b[2]), decodeBcd(b[3]), decodeBcd(b[4]), decodeBcd(b[5]), (decodeBcd(b[6])*10+int(b[7]>>4))*1e6)
	if e == nil && int(b[7]&15) != int(v.Weekday())+1 {
		e = fmt.Errorf("s7: weekday does not match date")
	}
	if e != nil {
		return time.Time{}, e
	}
	return v, e
}
func (h *Helper) SetDateTimeAtChecked(b []byte, p int, v time.Time) error {
	if e := span(b, p, 8); e != nil {
		return e
	}
	if v.Year() < 1990 || v.Year() > 2089 {
		return fmt.Errorf("s7: DATE_AND_TIME year outside 1990..2089")
	}
	ms := v.Nanosecond() / 1e6
	copy(b[p:], []byte{encodeBcd(v.Year() % 100), encodeBcd(int(v.Month())), encodeBcd(v.Day()), encodeBcd(v.Hour()), encodeBcd(v.Minute()), encodeBcd(v.Second()), encodeBcd(ms / 10), byte(ms%10<<4) | byte(v.Weekday()+1)})
	return nil
}
func (h *Helper) GetDateTimeAt(b []byte, p int) time.Time {
	v, _ := h.GetDateTimeAtChecked(b, p)
	return v
}
func (h *Helper) SetDateTimeAt(b []byte, p int, v time.Time) { _ = h.SetDateTimeAtChecked(b, p, v) }

var dateEpoch = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)

func (h *Helper) GetDateAtChecked(b []byte, p int) (time.Time, error) {
	var d uint16
	if e := h.GetValueAtChecked(b, p, &d); e != nil {
		return time.Time{}, e
	}
	return dateEpoch.AddDate(0, 0, int(d)), nil
}
func (h *Helper) SetDateAtChecked(b []byte, p int, v time.Time) error {
	d := time.Date(v.Year(), v.Month(), v.Day(), 0, 0, 0, 0, time.UTC).Sub(dateEpoch) / (24 * time.Hour)
	if d < 0 || d > 65535 {
		return fmt.Errorf("s7: DATE outside unsigned WORD range")
	}
	return h.SetValueAtChecked(b, p, uint16(d))
}
func (h *Helper) GetDateAt(b []byte, p int) time.Time    { v, _ := h.GetDateAtChecked(b, p); return v }
func (h *Helper) SetDateAt(b []byte, p int, v time.Time) { _ = h.SetDateAtChecked(b, p, v) }
func dayNano(v time.Time) uint64 {
	return uint64(v.Hour()*3600+v.Minute()*60+v.Second())*1e9 + uint64(v.Nanosecond())
}
func (h *Helper) GetTODAtChecked(b []byte, p int) (time.Time, error) {
	var n uint32
	if e := h.GetValueAtChecked(b, p, &n); e != nil {
		return time.Time{}, e
	}
	if n >= 86400000 {
		return time.Time{}, fmt.Errorf("s7: invalid TIME_OF_DAY")
	}
	return time.Unix(0, int64(n)*1e6).UTC(), nil
}
func (h *Helper) SetTODAtChecked(b []byte, p int, v time.Time) error {
	return h.SetValueAtChecked(b, p, uint32(dayNano(v)/1e6))
}
func (h *Helper) GetTODAt(b []byte, p int) time.Time    { v, _ := h.GetTODAtChecked(b, p); return v }
func (h *Helper) SetTODAt(b []byte, p int, v time.Time) { _ = h.SetTODAtChecked(b, p, v) }
func (h *Helper) GetLTODAtChecked(b []byte, p int) (time.Time, error) {
	var n uint64
	if e := h.GetValueAtChecked(b, p, &n); e != nil {
		return time.Time{}, e
	}
	if n >= 86400e9 {
		return time.Time{}, fmt.Errorf("s7: invalid LTIME_OF_DAY")
	}
	return time.Unix(0, int64(n)).UTC(), nil
}
func (h *Helper) SetLTODAtChecked(b []byte, p int, v time.Time) error {
	return h.SetValueAtChecked(b, p, dayNano(v))
}
func (h *Helper) GetLTODAt(b []byte, p int) time.Time    { v, _ := h.GetLTODAtChecked(b, p); return v }
func (h *Helper) SetLTODAt(b []byte, p int, v time.Time) { _ = h.SetLTODAtChecked(b, p, v) }
func (h *Helper) GetLDTAtChecked(b []byte, p int) (time.Time, error) {
	var n int64
	if e := h.GetValueAtChecked(b, p, &n); e != nil {
		return time.Time{}, e
	}
	if n < 0 {
		return time.Time{}, fmt.Errorf("s7: LDT precedes 1970")
	}
	return time.Unix(0, n).UTC(), nil
}
func (h *Helper) SetLDTAtChecked(b []byte, p int, v time.Time) error {
	n := v.UnixNano()
	if n < 0 || !time.Unix(0, n).Equal(v) {
		return fmt.Errorf("s7: LDT outside 1970..2262 range")
	}
	return h.SetValueAtChecked(b, p, n)
}
func (h *Helper) GetLDTAt(b []byte, p int) time.Time    { v, _ := h.GetLDTAtChecked(b, p); return v }
func (h *Helper) SetLDTAt(b []byte, p int, v time.Time) { _ = h.SetLDTAtChecked(b, p, v) }
func (h *Helper) GetDTLAtChecked(b []byte, p int) (time.Time, error) {
	if e := span(b, p, 12); e != nil {
		return time.Time{}, e
	}
	b = b[p : p+12]
	v, e := civil(int(binary.BigEndian.Uint16(b)), time.Month(b[2]), int(b[3]), int(b[5]), int(b[6]), int(b[7]), int(binary.BigEndian.Uint32(b[8:])))
	if e == nil && (v.Year() < 1970 || v.After(time.Date(2262, 4, 11, 23, 47, 16, 854775807, time.UTC)) || int(b[4]) != int(v.Weekday())+1) {
		e = fmt.Errorf("s7: invalid DTL range/weekday")
	}
	if e != nil {
		return time.Time{}, e
	}
	return v, e
}
func (h *Helper) SetDTLAtChecked(b []byte, p int, v time.Time) error {
	if e := span(b, p, 12); e != nil {
		return e
	}
	wall := time.Date(v.Year(), v.Month(), v.Day(), v.Hour(), v.Minute(), v.Second(), v.Nanosecond(), time.UTC)
	if v.Year() < 1970 || wall.After(time.Date(2262, 4, 11, 23, 47, 16, 854775807, time.UTC)) {
		return fmt.Errorf("s7: DTL outside supported range")
	}
	binary.BigEndian.PutUint16(b[p:], uint16(v.Year()))
	copy(b[p+2:], []byte{byte(v.Month()), byte(v.Day()), byte(v.Weekday() + 1), byte(v.Hour()), byte(v.Minute()), byte(v.Second())})
	binary.BigEndian.PutUint32(b[p+8:], uint32(v.Nanosecond()))
	return nil
}
func (h *Helper) GetDTLAt(b []byte, p int) time.Time { v, _ := h.GetDTLAtChecked(b, p); return v }
func (h *Helper) SetDTLAt(b []byte, p int, v time.Time) []byte {
	_ = h.SetDTLAtChecked(b, p, v)
	return b
}
func (h *Helper) GetS5TimeAtChecked(b []byte, p int) (time.Duration, error) {
	if e := span(b, p, 2); e != nil {
		return 0, e
	}
	x := b[p]
	if x&0xc0 != 0 || x&15 > 9 || !validBCD(b[p+1]) {
		return 0, fmt.Errorf("s7: invalid S5TIME")
	}
	scale := []int{10, 100, 1000, 10000}[x>>4&3]
	return time.Duration((int(x&15)*100+decodeBcd(b[p+1]))*scale) * time.Millisecond, nil
}
func (h *Helper) SetS5TimeAtChecked(b []byte, p int, v time.Duration) error {
	if e := span(b, p, 2); e != nil {
		return e
	}
	if v < 0 || v > 9990000*time.Millisecond {
		return fmt.Errorf("s7: S5TIME outside range")
	}
	for base, scale := range []int64{10, 100, 1000, 10000} {
		n := v.Milliseconds() / scale
		if n <= 999 {
			b[p] = byte(base<<4) | byte(n/100)
			b[p+1] = encodeBcd(int(n % 100))
			return nil
		}
	}
	return fmt.Errorf("s7: invalid S5TIME")
}
func (h *Helper) GetS5TimeAt(b []byte, p int) time.Duration {
	v, _ := h.GetS5TimeAtChecked(b, p)
	return v
}
func (h *Helper) SetS5TimeAt(b []byte, p int, v time.Duration) []byte {
	_ = h.SetS5TimeAtChecked(b, p, v)
	return b
}
func (h *Helper) SetStringAtChecked(b []byte, p, max int, v string) error {
	if max < 0 || max > 254 || len(v) > max {
		return fmt.Errorf("s7: invalid STRING length")
	}
	if e := span(b, p, 2+max); e != nil {
		return e
	}
	b[p], b[p+1] = byte(max), byte(len(v))
	clear(b[p+2 : p+2+max])
	copy(b[p+2:], v)
	return nil
}
func (h *Helper) GetStringAtChecked(b []byte, p int) (string, error) {
	if e := span(b, p, 2); e != nil {
		return "", e
	}
	max, n := int(b[p]), int(b[p+1])
	if max > 254 || n > max {
		return "", fmt.Errorf("s7: invalid STRING header")
	}
	if e := span(b, p+2, max); e != nil {
		return "", e
	}
	return string(b[p+2 : p+2+n]), nil
}
func (h *Helper) SetStringAt(b []byte, p, max int, v string) []byte {
	if max >= 0 && len(v) > max {
		v = v[:max]
	}
	_ = h.SetStringAtChecked(b, p, max, v)
	return b
}
func (h *Helper) GetStringAt(b []byte, p int) string { v, _ := h.GetStringAtChecked(b, p); return v }
func (h *Helper) SetWStringAtChecked(b []byte, p, max int, v string) error {
	r := []rune(v)
	if !utf8.ValidString(v) || max < 0 || max > 16382 || len(r) > max {
		return fmt.Errorf("s7: invalid WSTRING length")
	}
	for _, c := range r {
		if c > 0xffff || (c >= 0xd800 && c <= 0xdfff) {
			return fmt.Errorf("s7: character is not UCS-2")
		}
	}
	if e := span(b, p, 4+2*max); e != nil {
		return e
	}
	binary.BigEndian.PutUint16(b[p:], uint16(max))
	binary.BigEndian.PutUint16(b[p+2:], uint16(len(r)))
	clear(b[p+4 : p+4+2*max])
	for i, c := range r {
		binary.BigEndian.PutUint16(b[p+4+i*2:], uint16(c))
	}
	return nil
}
func (h *Helper) GetWStringAtChecked(b []byte, p int) (string, error) {
	if e := span(b, p, 4); e != nil {
		return "", e
	}
	max, n := int(binary.BigEndian.Uint16(b[p:])), int(binary.BigEndian.Uint16(b[p+2:]))
	if max > 16382 || n > max {
		return "", fmt.Errorf("s7: invalid WSTRING header")
	}
	if e := span(b, p+4, max*2); e != nil {
		return "", e
	}
	r := make([]rune, n)
	for i := range r {
		c := binary.BigEndian.Uint16(b[p+4+2*i:])
		if c >= 0xd800 && c <= 0xdfff {
			return "", fmt.Errorf("s7: invalid UCS-2")
		}
		r[i] = rune(c)
	}
	return string(r), nil
}
func (h *Helper) SetWStringAt(b []byte, p, max int, v string) []byte {
	r := []rune(v)
	if max >= 0 && len(r) > max {
		v = string(r[:max])
	}
	_ = h.SetWStringAtChecked(b, p, max, v)
	return b
}
func (h *Helper) GetWStringAt(b []byte, p int) string { v, _ := h.GetWStringAtChecked(b, p); return v }
func (h *Helper) GetCharsAt(b []byte, p, n int) string {
	if span(b, p, n) != nil {
		return ""
	}
	return string(b[p : p+n])
}
func (h *Helper) SetCharsAtChecked(b []byte, p int, v string) error {
	if e := span(b, p, len(v)); e != nil {
		return e
	}
	copy(b[p:], v)
	return nil
}
func (h *Helper) SetCharsAt(b []byte, p int, v string) { _ = h.SetCharsAtChecked(b, p, v) }
func (h *Helper) GetCounterChecked(v uint16) (int, error) {
	if v&0xf000 != 0 || (v>>8)&15 > 9 || (v>>4)&15 > 9 || v&15 > 9 {
		return 0, fmt.Errorf("s7: invalid counter BCD")
	}
	return int(v>>8)*100 + int(v>>4&15)*10 + int(v&15), nil
}
func (h *Helper) ToCounterChecked(v int) (uint16, error) {
	if v < 0 || v > 999 {
		return 0, fmt.Errorf("s7: counter outside 0..999")
	}
	return uint16(v/100<<8 | v/10%10<<4 | v%10), nil
}
func (h *Helper) GetCounter(v uint16) int { n, _ := h.GetCounterChecked(v); return n }
func (h *Helper) ToCounter(v int) uint16  { n, _ := h.ToCounterChecked(v); return n }
func (h *Helper) GetCounterAt(b []uint16, p int) int {
	if p < 0 || p >= len(b) {
		return 0
	}
	return h.GetCounter(b[p])
}
func (h *Helper) SetCounterAt(b []uint16, p, v int) []uint16 {
	if p >= 0 && p < len(b) {
		if n, e := h.ToCounterChecked(v); e == nil {
			b[p] = n
		}
	}
	return b
}
func (h *Helper) SetBoolAt(b byte, p uint, v bool) byte {
	if p > 7 {
		return b
	}
	if v {
		return b | 1<<p
	}
	return b &^ (1 << p)
}
func (h *Helper) GetBoolAt(b byte, p uint) bool { return p < 8 && b&(1<<p) != 0 }
