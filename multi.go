package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

import (
	"encoding/binary"
	"fmt"
)

// S7DataItem describes one S7ANY variable. Start is a byte offset and Bit is
// 0..7 for bit variables. CT/TM Start is an element index. Data contains raw
// protocol bytes (big-endian for multibyte types), not converted Go values.
type S7DataItem struct {
	Area, WordLen, DBNumber, Start, Bit, Amount int
	Data                                        []byte
	Error                                       string
}

func validateItem(item S7DataItem, wire bool) (int, error) {
	width := dataSizeByte(item.WordLen)
	if width == 0 || item.Amount < 1 || item.Start < 0 || item.DBNumber < 0 || item.DBNumber > 65535 {
		return 0, fmt.Errorf("s7: invalid item parameters")
	}
	if wire && item.Amount > 65535 {
		return 0, fmt.Errorf("s7: item amount exceeds S7ANY field")
	}
	switch item.Area {
	case s7areape, s7areapa, s7areamk, s7areadb:
		if item.WordLen == s7wlcounter || item.WordLen == s7wltimer {
			return 0, fmt.Errorf("s7: counter/timer requires matching area")
		}
		if item.Start > 0x1fffff || item.Amount > (0x200000-item.Start)/width {
			return 0, fmt.Errorf("s7: address exceeds 24-bit bit-address field")
		}
	case s7areact, s7areatm:
		expected := s7wlcounter
		if item.Area == s7areatm {
			expected = s7wltimer
		}
		if item.WordLen != expected || item.Start > 65535 || item.Amount > 65536-item.Start {
			return 0, fmt.Errorf("s7: invalid counter/timer index")
		}
	default:
		return 0, fmt.Errorf("s7: unsupported area %02x", item.Area)
	}
	if item.Area != s7areadb && item.DBNumber != 0 {
		return 0, fmt.Errorf("s7: non-DB area requires DBNumber zero")
	}
	if item.WordLen == s7wlbit {
		if item.Amount != 1 || item.Bit < 0 || item.Bit > 7 {
			return 0, fmt.Errorf("s7: bit item requires Amount=1 and Bit=0..7")
		}
	} else if item.Bit != 0 {
		return 0, fmt.Errorf("s7: Bit applies only to bit variables")
	}
	size := item.Amount * width
	if len(item.Data) < size {
		return 0, fmt.Errorf("s7: item buffer needs %d bytes, got %d", size, len(item.Data))
	}
	return size, nil
}

func itemParameter(item S7DataItem) []byte {
	p := make([]byte, 12)
	p[0], p[1], p[2], p[3], p[8] = 0x12, 10, 0x10, byte(item.WordLen), byte(item.Area)
	binary.BigEndian.PutUint16(p[4:6], uint16(item.Amount))
	binary.BigEndian.PutUint16(p[6:8], uint16(item.DBNumber))
	address := item.Start
	if item.WordLen != s7wlcounter && item.WordLen != s7wltimer {
		address *= 8
		if item.WordLen == s7wlbit {
			address += item.Bit
		}
	}
	p[9], p[10], p[11] = byte(address>>16), byte(address>>8), byte(address)
	return p
}
func itemTransport(word, size, amount int) (byte, int) {
	switch word {
	case s7wlbit:
		return tsResBit, amount
	case s7wlChar, s7wlcounter, s7wltimer:
		return tsResOctet, size
	case s7wlint, s7wldint:
		return tsResInt, size * 8
	case s7wlreal:
		return tsResReal, size
	default:
		return tsResByte, size * 8
	}
}
func validItemTransport(word int, transport byte) bool {
	switch word {
	case s7wlbit:
		return transport == tsResBit
	case s7wlcounter, s7wltimer:
		return transport == tsResOctet
	case s7wlChar:
		return transport == tsResOctet || transport == tsResByte
	case s7wlint:
		return transport == tsResInt || transport == tsResByte
	case s7wldint:
		return transport == tsResInt || transport == 6 || transport == tsResByte
	case s7wlreal:
		return transport == tsResReal || transport == tsResByte
	default:
		return transport == tsResByte
	}
}
func (mb *client) validateItems(items []S7DataItem, count int, write bool) ([]int, int, error) {
	if count < 1 || count > 20 || count > len(items) {
		return nil, 0, fmt.Errorf("s7: item count must be 1..20 and within slice")
	}
	sizes := make([]int, count)
	// PDU sizes exclude the 7-byte ISO envelope.
	request, response := 12+12*count, 14
	for i := 0; i < count; i++ {
		size, err := validateItem(items[i], true)
		if err != nil {
			return nil, 0, fmt.Errorf("s7: item %d: %w", i, err)
		}
		sizes[i] = size
		_, encodedLength := itemTransport(items[i].WordLen, size, items[i].Amount)
		if encodedLength > 65535 {
			return nil, 0, fmt.Errorf("s7: item data length exceeds transport field")
		}
		if write {
			if items[i].WordLen == s7wlbit && items[i].Data[0] > 1 {
				return nil, 0, fmt.Errorf("s7: bit data must be 0 or 1")
			}
			request += 4 + size
			if i < count-1 && size%2 != 0 {
				request++
			}
			response++
		} else {
			response += 4 + size
			if i < count-1 && size%2 != 0 {
				response++
			}
		}
	}
	pdu, err := mb.pduSize()
	if err != nil {
		return nil, 0, err
	}
	if request > pdu || response > pdu {
		return nil, 0, fmt.Errorf("s7: item request or reply exceeds negotiated PDU (%d/%d > %d)", request, response, pdu)
	}
	return sizes, pdu, nil
}

func (mb *client) AGWriteMulti(items []S7DataItem, count int) error {
	sizes, _, err := mb.validateItems(items, count, true)
	if err != nil {
		return err
	}
	params := []byte{5, byte(count)}
	var data []byte
	for i := 0; i < count; i++ {
		params = append(params, itemParameter(items[i])...)
		transport, length := itemTransport(items[i].WordLen, sizes[i], items[i].Amount)
		data = append(data, 0, transport, byte(length>>8), byte(length))
		data = append(data, items[i].Data[:sizes[i]]...)
		if i < count-1 && sizes[i]%2 != 0 {
			data = append(data, 0)
		}
	}
	request := NewProtocolDataUnit(jobPacket(5, params, data))
	reply, err := mb.send(&request)
	if err != nil {
		return err
	}
	m, err := parseS7(reply.Data)
	if err != nil {
		return mb.badReply(reply, err)
	}
	if m.kind != s7AckData || len(m.params) != 2 || m.params[1] != byte(count) || len(m.data) != count {
		return mb.badReply(reply, fmt.Errorf("s7: invalid write reply item count/length"))
	}
	for i := 0; i < count; i++ {
		items[i].Error = ""
		if e := itemError(m.data[i]); e != nil {
			items[i].Error = e.Error()
		}
	}
	return nil
}

func (mb *client) AGReadMulti(items []S7DataItem, count int) error {
	sizes, _, err := mb.validateItems(items, count, false)
	if err != nil {
		return err
	}
	params := []byte{4, byte(count)}
	for i := 0; i < count; i++ {
		params = append(params, itemParameter(items[i])...)
	}
	request := NewProtocolDataUnit(jobPacket(4, params, nil))
	reply, err := mb.send(&request)
	if err != nil {
		return err
	}
	m, err := parseS7(reply.Data)
	if err != nil {
		return mb.badReply(reply, err)
	}
	if m.kind != s7AckData || len(m.params) != 2 || m.params[1] != byte(count) {
		return mb.badReply(reply, fmt.Errorf("s7: invalid read reply item count"))
	}
	results := make([][]byte, count)
	itemErrors := make([]string, count)
	offset := 0
	for i := 0; i < count; i++ {
		if len(m.data)-offset < 4 {
			return mb.badReply(reply, fmt.Errorf("s7: truncated read item header"))
		}
		status, transport := m.data[offset], m.data[offset+1]
		length := int(binary.BigEndian.Uint16(m.data[offset+2 : offset+4]))
		offset += 4
		if e := itemError(status); e != nil {
			// Snap7 reports the four-byte error header as its length; there is
			// no following payload. Other peers report zero. Neither consumes data.
			if (length != 0 && length != 4) || transport != 0 {
				return mb.badReply(reply, fmt.Errorf("s7: invalid failed-item payload"))
			}
			itemErrors[i] = e.Error()
			continue
		}
		size, e := dataLengthBytes(transport, length)
		if e != nil {
			return mb.badReply(reply, e)
		}
		if !validItemTransport(items[i].WordLen, transport) || size != sizes[i] || size > len(m.data)-offset || (transport == tsResBit && length != items[i].Amount) {
			return mb.badReply(reply, fmt.Errorf("s7: read item transport or payload length mismatch"))
		}
		results[i] = m.data[offset : offset+size]
		offset += size
		if i < count-1 && size%2 != 0 {
			// Padding has no defined value; validate its presence, not its contents.
			if offset >= len(m.data) {
				return mb.badReply(reply, fmt.Errorf("s7: missing/invalid item padding"))
			}
			offset++
		}
	}
	if offset != len(m.data) {
		return mb.badReply(reply, fmt.Errorf("s7: trailing read-item data"))
	}
	// Validate every item before publishing any values to caller buffers.
	for i := 0; i < count; i++ {
		items[i].Error = itemErrors[i]
		if itemErrors[i] == "" {
			copy(items[i].Data, results[i])
		}
	}
	return nil
}
