package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	s7areape           = 0x81
	s7areapa           = 0x82
	s7areamk           = 0x83
	s7areadb           = 0x84
	s7areact           = 0x1c
	s7areatm           = 0x1d
	s7wlbit            = 1
	s7wlbyte           = 2
	s7wlChar           = 3
	s7wlword           = 4
	s7wlint            = 5
	s7wldword          = 6
	s7wldint           = 7
	s7wlreal           = 8
	s7wlcounter        = 0x1c
	s7wltimer          = 0x1d
	s7CpuStatusUnknown = 0
	s7CpuStatusRun     = 8
	s7CpuStatusStop    = 4
	sizeHeaderRead     = 31
	sizeHeaderWrite    = 35
	tsResBit           = 3
	tsResByte          = 4
	tsResInt           = 5
	tsResReal          = 7
	tsResOctet         = 9
)

type ClientHandler interface {
	Packager
	Transporter
}
type client struct {
	packager    Packager
	transporter Transporter
	sequence    atomic.Uint32
}

func NewClient(handler ClientHandler) Client { return &client{packager: handler, transporter: handler} }
func NewClient2(packager Packager, transporter Transporter) Client {
	return &client{packager: packager, transporter: transporter}
}

func (mb *client) AGReadDB(db, start, size int, b []byte) error {
	return mb.readArea(s7areadb, db, start, size, s7wlbyte, b)
}
func (mb *client) AGWriteDB(db, start, size int, b []byte) error {
	return mb.writeArea(s7areadb, db, start, size, s7wlbyte, b)
}
func (mb *client) AGReadMB(start, size int, b []byte) error {
	return mb.readArea(s7areamk, 0, start, size, s7wlbyte, b)
}
func (mb *client) AGWriteMB(start, size int, b []byte) error {
	return mb.writeArea(s7areamk, 0, start, size, s7wlbyte, b)
}
func (mb *client) AGReadEB(start, size int, b []byte) error {
	return mb.readArea(s7areape, 0, start, size, s7wlbyte, b)
}
func (mb *client) AGWriteEB(start, size int, b []byte) error {
	return mb.writeArea(s7areape, 0, start, size, s7wlbyte, b)
}
func (mb *client) AGReadAB(start, size int, b []byte) error {
	return mb.readArea(s7areapa, 0, start, size, s7wlbyte, b)
}
func (mb *client) AGWriteAB(start, size int, b []byte) error {
	return mb.writeArea(s7areapa, 0, start, size, s7wlbyte, b)
}

// Timer/Counter buffers contain two big-endian protocol bytes per element.
func (mb *client) AGReadTM(start, amount int, b []byte) error {
	return mb.readArea(s7areatm, 0, start, amount, s7wltimer, b)
}
func (mb *client) AGWriteTM(start, amount int, b []byte) error {
	return mb.writeArea(s7areatm, 0, start, amount, s7wltimer, b)
}
func (mb *client) AGReadCT(start, amount int, b []byte) error {
	return mb.readArea(s7areact, 0, start, amount, s7wlcounter, b)
}
func (mb *client) AGWriteCT(start, amount int, b []byte) error {
	return mb.writeArea(s7areact, 0, start, amount, s7wlcounter, b)
}

func (mb *client) readArea(area, db, start, amount, word int, b []byte) error {
	return mb.transferArea(false, area, db, start, amount, word, b)
}
func (mb *client) writeArea(area, db, start, amount, word int, b []byte) error {
	return mb.transferArea(true, area, db, start, amount, word, b)
}
func (mb *client) transferArea(write bool, area, db, start, amount, word int, b []byte) error {
	if area == s7areact {
		word = s7wlcounter
	}
	if area == s7areatm {
		word = s7wltimer
	}
	item := S7DataItem{Area: area, DBNumber: db, Start: start, WordLen: word, Amount: amount, Data: b}
	if word == s7wlbit {
		item.Start, item.Bit = start/8, start%8
	}
	if _, err := validateItem(item, false); err != nil {
		return err
	}
	pdu, err := mb.pduSize()
	if err != nil {
		return err
	}
	overhead := 18
	if write {
		overhead = 28
	}
	width := dataSizeByte(word)
	maxElements := (pdu - overhead) / width
	// Some data transport sizes encode BITS in a 16-bit length field.
	maxPayload := 65535
	transport, _ := itemTransport(word, width, 1)
	if transport == tsResByte || transport == tsResInt {
		maxPayload /= 8
	}
	if maxElements > maxPayload/width {
		maxElements = maxPayload / width
	}
	if maxElements < 1 {
		return fmt.Errorf("s7: negotiated PDU cannot hold one element")
	}
	for remaining, offset := amount, 0; remaining > 0; {
		count := remaining
		if count > maxElements {
			count = maxElements
		}
		if count > 65535 {
			count = 65535
		}
		part := item
		part.Amount = count
		part.Data = b[offset : offset+count*width]
		items := []S7DataItem{part}
		if write {
			err = mb.AGWriteMulti(items, 1)
		} else {
			err = mb.AGReadMulti(items, 1)
		}
		if err != nil {
			return err
		}
		if items[0].Error != "" {
			return fmt.Errorf("%s", items[0].Error)
		}
		remaining -= count
		offset += count * width
		if word == s7wlcounter || word == s7wltimer {
			item.Start += count
		} else {
			item.Start += count * width
		}
	}
	return nil
}

type protocolReply struct {
	Data       []byte
	invalidate func()
}

func (mb *client) send(request *ProtocolDataUnit) (*protocolReply, error) {
	if mb.transporter == nil || mb.packager == nil || request == nil {
		return nil, fmt.Errorf("s7: missing protocol backend")
	}
	if _, err := parseS7(request.Data); err != nil {
		return nil, err
	}
	wire := append([]byte(nil), request.Data...)
	reference := uint16(mb.sequence.Add(1))
	if reference == 0 {
		reference = uint16(mb.sequence.Add(1))
	}
	if allocator, ok := mb.transporter.(interface{ NextReference() uint16 }); ok {
		reference = allocator.NextReference()
	}
	binary.BigEndian.PutUint16(wire[11:13], reference)
	var response []byte
	var err error
	var invalidate func()
	if scoped, ok := mb.transporter.(SessionTransporter); ok {
		response, invalidate, err = scoped.SendWithSession(wire)
	} else {
		response, err = mb.transporter.Send(wire)
		if closer, ok := mb.transporter.(interface{ Close() error }); ok {
			invalidate = func() { _ = closer.Close() }
		}
	}
	if err != nil {
		return nil, err
	}
	if err = verifyS7(wire, response); err != nil {
		if invalidate != nil {
			invalidate()
		}
		return nil, err
	}
	if err = mb.packager.Verify(wire, response); err != nil {
		if invalidate != nil {
			invalidate()
		}
		return nil, err
	}
	res := &ProtocolDataUnit{Data: response}
	if err = responseError(res); err != nil {
		return nil, err
	}
	return &protocolReply{Data: response, invalidate: invalidate}, nil
}
func (mb *client) badReply(reply *protocolReply, err error) error {
	if reply != nil && reply.invalidate != nil {
		reply.invalidate()
	}
	return err
}
func responseError(response *ProtocolDataUnit) error {
	if response == nil {
		return fmt.Errorf("s7: nil response")
	}
	m, err := parseS7(response.Data)
	if err != nil {
		return err
	}
	return messageError(m)
}
func dataSizeByte(word int) int {
	switch word {
	case s7wlbit, s7wlbyte, s7wlChar:
		return 1
	case s7wlword, s7wlint, s7wlcounter, s7wltimer:
		return 2
	case s7wldword, s7wldint, s7wlreal:
		return 4
	}
	return 0
}

type parsedAddress struct{ area, db, start, bit, word int }

func parseAddress(variable string) (a parsedAddress, err error) {
	variable = strings.ToUpper(strings.ReplaceAll(variable, " ", ""))
	invalid := func() (parsedAddress, error) { return parsedAddress{}, fmt.Errorf("s7: invalid address %q", variable) }
	parse := func(s string) (int, error) {
		if s == "" {
			return 0, fmt.Errorf("empty number")
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("invalid number")
			}
		}
		return strconv.Atoi(s)
	}
	if strings.HasPrefix(variable, "DB") {
		parts := strings.Split(variable, ".")
		if len(parts) < 2 || len(parts) > 3 || len(parts[0]) < 3 || len(parts[1]) < 4 {
			return invalid()
		}
		a.area = s7areadb
		a.db, err = parse(parts[0][2:])
		if err != nil {
			return invalid()
		}
		a.start, err = parse(parts[1][3:])
		if err != nil {
			return invalid()
		}
		switch parts[1][:3] {
		case "DBB":
			a.word = s7wlbyte
		case "DBW":
			a.word = s7wlword
		case "DBD":
			a.word = s7wldword
		case "DBX":
			a.word = s7wlbit
		default:
			return invalid()
		}
		if a.word == s7wlbit {
			if len(parts) != 3 {
				return invalid()
			}
			a.bit, err = parse(parts[2])
			if err != nil {
				return invalid()
			}
		} else if len(parts) != 2 {
			return invalid()
		}
	} else {
		if len(variable) < 2 {
			return invalid()
		}
		switch variable[0] {
		case 'I', 'E':
			a.area = s7areape
		case 'Q', 'O', 'A':
			a.area = s7areapa
		case 'M':
			a.area = s7areamk
		case 'C', 'Z':
			a.area = s7areact
		case 'T':
			a.area = s7areatm
		default:
			return invalid()
		}
		if a.area == s7areact || a.area == s7areatm {
			a.start, err = parse(variable[1:])
			a.word = s7wlcounter
			if a.area == s7areatm {
				a.word = s7wltimer
			}
		} else {
			rest := variable[1:]
			a.word = s7wlbit
			switch rest[0] {
			case 'B':
				a.word = s7wlbyte
				rest = rest[1:]
			case 'W':
				a.word = s7wlword
				rest = rest[1:]
			case 'D':
				a.word = s7wldword
				rest = rest[1:]
			}
			fields := strings.Split(rest, ".")
			if a.word == s7wlbit {
				if len(fields) != 2 {
					return invalid()
				}
				a.bit, err = parse(fields[1])
				if err != nil {
					return invalid()
				}
			} else if len(fields) != 1 {
				return invalid()
			}
			a.start, err = parse(fields[0])
		}
		if err != nil {
			return invalid()
		}
	}
	check := S7DataItem{Area: a.area, DBNumber: a.db, Start: a.start, Bit: a.bit, WordLen: a.word, Amount: 1, Data: make([]byte, dataSizeByte(a.word))}
	if _, err = validateItem(check, true); err != nil {
		return invalid()
	}
	return a, nil
}

// Read accepts DBn.DBB/W/D/Xoffset[.bit], I/E, Q/O/A and M B/W/D or
// byte.bit addresses, plus Tn and C/Zn. Words/dwords are returned unsigned;
// bits return bool and timers/counters return their raw uint16 representation.
func (mb *client) Read(variable string, b []byte) (interface{}, error) {
	a, err := parseAddress(variable)
	if err != nil {
		return nil, err
	}
	size := dataSizeByte(a.word)
	if len(b) < size {
		return nil, fmt.Errorf("s7: output buffer too small")
	}
	item := S7DataItem{Area: a.area, DBNumber: a.db, Start: a.start, Bit: a.bit, WordLen: a.word, Amount: 1, Data: b[:size]}
	items := []S7DataItem{item}
	if err = mb.AGReadMulti(items, 1); err != nil {
		return nil, err
	}
	if items[0].Error != "" {
		return nil, fmt.Errorf("%s", items[0].Error)
	}
	switch a.word {
	case s7wlbit:
		return b[0] != 0, nil
	case s7wlbyte:
		return b[0], nil
	case s7wlword, s7wltimer, s7wlcounter:
		return binary.BigEndian.Uint16(b), nil
	case s7wldword:
		return binary.BigEndian.Uint32(b), nil
	}
	return nil, fmt.Errorf("s7: unsupported value type")
}
