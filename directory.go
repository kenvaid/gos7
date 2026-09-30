package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	blockOB  = 56
	blockDB  = 65
	blockSDB = 66
	blockFC  = 67
	blockSFC = 68
	blockFB  = 69
	blockSFB = 70
)

type S7BlocksList struct{ OBList, FBList, FCList, SFBList, SFCList, DBList, SDBList []int }

func (mb *client) PGListBlocks() (list S7BlocksList, err error) {
	for _, entry := range []struct {
		kind   byte
		target *[]int
	}{{blockOB, &list.OBList}, {blockDB, &list.DBList}, {blockFC, &list.FCList}, {blockFB, &list.FBList}, {blockSDB, &list.SDBList}, {blockSFB, &list.SFBList}, {blockSFC, &list.SFCList}} {
		*entry.target, err = mb.pgBlockList(entry.kind)
		if err != nil {
			return list, err
		}
	}
	return list, nil
}
func validBlockType(kind int) bool {
	switch kind {
	case blockOB, blockDB, blockSDB, blockFC, blockSFC, blockFB, blockSFB:
		return true
	}
	return false
}
func (mb *client) pgBlockList(kind byte) (list []int, err error) {
	if !validBlockType(int(kind)) {
		return nil, fmt.Errorf("s7: unsupported block type")
	}
	first := true
	sequence := byte(0)
	for {
		var data []byte
		if first {
			data = append(append([]byte(nil), s7PGBlockListTelegram...), kind)
		} else {
			params := []byte{0, 1, 0x12, 8, 0x11, 0x43, 2, sequence, 0, 0, 0, 0}
			data = userDataRequest(params, []byte{0x0a, 0, 0, 0})
		}
		request := NewProtocolDataUnit(data)
		response, e := mb.send(&request)
		if e != nil {
			// A type with no blocks is an empty directory, not a failed listing.
			var cpu *S7Error
			if first && errors.As(e, &cpu) && cpu.High == 0xd2 && cpu.Low == 0x0e {
				return nil, nil
			}
			return nil, e
		}
		params, payload, e := userDataPayload(response.Data)
		if e != nil {
			return nil, mb.badReply(response, e)
		}
		if len(payload)%4 != 0 || params[9] > 1 {
			return nil, mb.badReply(response, fmt.Errorf("s7: malformed block-list fragment"))
		}
		list = append(list, dataToBlocks(payload)...)
		if params[9] == 0 {
			return list, nil
		}
		if len(payload) == 0 {
			return nil, mb.badReply(response, fmt.Errorf("s7: non-progressing block-list fragment"))
		}
		sequence = params[7]
		first = false
	}
}
func dataToBlocks(data []byte) []int {
	blocks := make([]int, 0, len(data)/4)
	for i := 0; i+4 <= len(data); i += 4 {
		blocks = append(blocks, int(binary.BigEndian.Uint16(data[i:i+2])))
	}
	return blocks
}
