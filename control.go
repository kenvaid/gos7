package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

import "fmt"

func (mb *client) control(template []byte, function byte) error {
	request := NewProtocolDataUnit(append([]byte(nil), template...))
	response, err := mb.send(&request)
	if err != nil {
		return err
	}
	m, err := parseS7(response.Data)
	if err != nil {
		return mb.badReply(response, err)
	}
	if m.kind != s7AckData || len(m.data) != 0 || len(m.params) < 1 || len(m.params) > 2 || m.params[0] != function {
		return mb.badReply(response, fmt.Errorf("s7: invalid control acknowledgement"))
	}
	if len(m.params) == 2 && m.params[1] != 0 {
		return fmt.Errorf("s7: control acknowledgement status %02x", m.params[1])
	}
	return nil
}
func (mb *client) PLCHotStart() error  { return mb.control(s7HotStartTelegram, pduStart) }
func (mb *client) PLCColdStart() error { return mb.control(s7ColdStartTelegram, pduStart) }
func (mb *client) PLCStop() error      { return mb.control(s7StopTelegram, pduStop) }
func (mb *client) PLCGetStatus() (int, error) {
	szl, _, err := mb.readSzl(0x0424, 0)
	if err != nil {
		return 0, err
	}
	if len(szl.Data) < 4 {
		return 0, szl.fail(fmt.Errorf("s7: truncated CPU status"))
	}
	status := int(szl.Data[3])
	if status != 0 && status != 8 && status != 4 {
		status = s7CpuStatusStop
	}
	return status, nil
}
