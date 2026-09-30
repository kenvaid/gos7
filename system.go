package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type SZLHeader struct{ LengthHeader, NumberOfDataRecord uint16 }
type S7SZL struct {
	Header SZLHeader
	Data   []byte
}

type szlResult struct {
	S7SZL
	invalidate func()
}

func (szl szlResult) fail(err error) error {
	if szl.invalidate != nil {
		szl.invalidate()
	}
	return err
}

type S7SZLList struct {
	Header SZLHeader
	Data   []uint16
}

// Protection levels and selector settings from SZL 0232, index 4.
type S7Protection struct{ SchSchal, SchPar, SchRel, BartSch, AnlSch uint }
type S7OrderCode struct {
	Code       string
	V1, V2, V3 byte
}
type S7CpuInfo struct{ ModuleTypeName, SerialNumber, ASName, Copyright, ModuleName string }
type S7CpInfo struct{ MaxPduLength, MaxConnections, MaxMpiRate, MaxBusRate int }

func plcText(data []byte) string { return strings.TrimRight(string(data), " \x00") }
func (mb *client) GetCPUInfo() (info S7CpuInfo, err error) {
	szl, _, err := mb.readSzl(0x001c, 0)
	if err != nil {
		return info, err
	}
	if szl.Header.LengthHeader != 34 || len(szl.Data) == 0 {
		return info, szl.fail(fmt.Errorf("s7: truncated CPU information"))
	}
	// SZL 001C identifies records by index, not by their list position.
	for offset := 0; offset < len(szl.Data); offset += 34 {
		record := szl.Data[offset : offset+34]
		switch binary.BigEndian.Uint16(record[:2]) {
		case 1:
			info.ASName = plcText(record[2:26])
		case 2:
			info.ModuleName = plcText(record[2:26])
		case 4:
			info.Copyright = plcText(record[2:28])
		case 5:
			info.SerialNumber = plcText(record[2:26])
		case 7:
			info.ModuleTypeName = plcText(record[2:34])
		}
	}
	return info, nil
}
func (mb *client) GetCPInfo() (info S7CpInfo, err error) {
	szl, _, err := mb.readSzl(0x0131, 1)
	if err != nil {
		return info, err
	}
	if len(szl.Data) < 14 {
		return info, szl.fail(fmt.Errorf("s7: truncated CP information"))
	}
	info.MaxPduLength = int(binary.BigEndian.Uint16(szl.Data[2:4]))
	info.MaxConnections = int(binary.BigEndian.Uint16(szl.Data[4:6]))
	info.MaxMpiRate = int(binary.BigEndian.Uint32(szl.Data[6:10]))
	info.MaxBusRate = int(binary.BigEndian.Uint32(szl.Data[10:14]))
	return info, nil
}
func (mb *client) GetOrderCode() (info S7OrderCode, err error) {
	szl, _, err := mb.readSzl(0x0011, 0)
	if err != nil {
		return info, err
	}
	if szl.Header.LengthHeader != 28 || len(szl.Data) == 0 {
		return info, szl.fail(fmt.Errorf("s7: truncated order-code record"))
	}
	found := false
	for offset := 0; offset < len(szl.Data); offset += 28 {
		record := szl.Data[offset : offset+28]
		switch binary.BigEndian.Uint16(record[:2]) {
		case 1:
			info.Code = plcText(record[2:22])
			found = true
		case 7:
			info.V1, info.V2, info.V3 = record[25], record[26], record[27]
		}
	}
	if !found {
		return info, szl.fail(fmt.Errorf("s7: missing module identification record"))
	}
	return info, nil
}

func (mb *client) readSzl(id, index int) (szl szlResult, size int, err error) {
	if id < 0 || id > 65535 || index < 0 || index > 65535 {
		return szl, 0, fmt.Errorf("s7: invalid SZL id/index")
	}
	first := true
	sequence := byte(0)
	expected := 0
	for {
		var data []byte
		if first {
			data = append([]byte(nil), s7SZLFirstTelegram...)
			binary.BigEndian.PutUint16(data[29:31], uint16(id))
			binary.BigEndian.PutUint16(data[31:33], uint16(index))
		} else {
			data = append([]byte(nil), s7SZLNextTelegram...)
			data[24] = sequence
		}
		request := NewProtocolDataUnit(data)
		response, e := mb.send(&request)
		if e != nil {
			return szl, 0, e
		}
		szl.invalidate = response.invalidate
		params, payload, e := userDataPayload(response.Data)
		if e != nil {
			return szl, 0, mb.badReply(response, e)
		}
		if params[9] > 1 {
			return szl, 0, mb.badReply(response, fmt.Errorf("s7: invalid SZL fragment flag"))
		}
		if first {
			if len(payload) < 8 || binary.BigEndian.Uint16(payload[:2]) != uint16(id) || binary.BigEndian.Uint16(payload[2:4]) != uint16(index) {
				return szl, 0, mb.badReply(response, fmt.Errorf("s7: invalid SZL identity/header"))
			}
			szl.Header.LengthHeader = binary.BigEndian.Uint16(payload[4:6])
			szl.Header.NumberOfDataRecord = binary.BigEndian.Uint16(payload[6:8])
			expected = int(szl.Header.LengthHeader) * int(szl.Header.NumberOfDataRecord)
			if szl.Header.LengthHeader == 0 && szl.Header.NumberOfDataRecord != 0 {
				return szl, 0, mb.badReply(response, fmt.Errorf("s7: invalid SZL record width"))
			}
			payload = payload[8:]
		}
		// Continuation payload starts immediately after the 4-byte data header;
		// it has no repeated SZL id, index or record header.
		if len(payload) > expected-len(szl.Data) {
			return szl, 0, mb.badReply(response, fmt.Errorf("s7: SZL data exceeds declared records"))
		}
		szl.Data = append(szl.Data, payload...)
		if params[9] == 0 {
			if len(szl.Data) != expected {
				return szl, 0, mb.badReply(response, fmt.Errorf("s7: incomplete SZL records"))
			}
			return szl, len(szl.Data), nil
		}
		if len(payload) == 0 || len(szl.Data) == expected {
			return szl, 0, mb.badReply(response, fmt.Errorf("s7: non-progressing SZL fragment"))
		}
		sequence = params[7]
		first = false
	}
}
