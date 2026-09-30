package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

import (
	"encoding/binary"
	"fmt"
	"time"
)

// S7BlockInfo Managed Block Info
type S7BlockInfo struct {
	BlkType   int
	BlkNumber int
	BlkLang   int
	BlkFlags  int
	MC7Size   int // The real size in bytes
	LoadSize  int
	LocalData int
	SBBLength int
	CheckSum  int
	Version   int
	// Chars info
	CodeDate string
	IntfDate string
	Author   string
	Family   string
	Header   string
}

func (mb *client) DBFill(dbnumber int, fillChar int) (err error) {
	if fillChar < 0 || fillChar > 255 {
		return fmt.Errorf("s7: fill byte outside 0..255")
	}
	// bi := S7BlockInfo{}
	bi, err := mb.GetAgBlockInfo(blockDB, dbnumber)
	if err == nil {
		if bi.MC7Size == 0 {
			return nil
		}
		buffer := make([]byte, bi.MC7Size)
		for c := 0; c < bi.MC7Size; c++ {
			buffer[c] = byte(fillChar)
		}
		err = mb.AGWriteDB(dbnumber, 0, bi.MC7Size, buffer)
	}
	return
}

func (mb *client) DBGet(dbnumber int, usrdata []byte, size int) (err error) {
	if size < 0 || size > len(usrdata) {
		return fmt.Errorf("s7: invalid DBGet buffer capacity")
	}
	// bi := S7BlockInfo{}
	bi, err := mb.GetAgBlockInfo(blockDB, dbnumber)
	if err == nil {
		if dbSize := bi.MC7Size; dbSize <= size {
			if dbSize == 0 {
				return nil
			}
			size = dbSize
			err = mb.AGReadDB(dbnumber, 0, dbSize, usrdata)
			if err == nil {
				size = dbSize
			}
		} else {
			err = fmt.Errorf("%s", ErrorText(errCliBufferTooSmall))
		}
	}
	return
}

// internal class returns info about a given block in PLC memory.
// This function is very useful if you need to read or write data in a DB
// which you do not know the size in advance ( MC7Size).
func (mb *client) GetAgBlockInfo(blocktype int, blocknum int) (info S7BlockInfo, err error) {
	if !validBlockType(blocktype) || blocknum < 0 || blocknum > 65535 {
		return info, fmt.Errorf("s7: invalid block type/number")
	}
	data := append([]byte(nil), s7BlockInfoTelegram...)
	data[30] = byte(blocktype)
	copy(data[31:36], fmt.Sprintf("%05d", blocknum))
	request := NewProtocolDataUnit(data)
	response, err := mb.send(&request)
	if err != nil {
		return info, err
	}
	_, p, err := userDataPayload(response.Data)
	if err != nil {
		return info, mb.badReply(response, err)
	}
	if len(p) < 70 {
		return info, mb.badReply(response, fmt.Errorf("s7: truncated block information"))
	}
	info.BlkFlags = int(p[9])
	info.BlkLang = int(p[10])
	info.BlkType = int(p[11])
	info.BlkNumber = int(binary.BigEndian.Uint16(p[12:]))
	info.LoadSize = int(binary.BigEndian.Uint32(p[14:]))
	info.CodeDate = siemensTimestamp(int64(binary.BigEndian.Uint16(p[26:])))
	info.IntfDate = siemensTimestamp(int64(binary.BigEndian.Uint16(p[32:])))
	info.SBBLength = int(binary.BigEndian.Uint16(p[34:]))
	info.LocalData = int(binary.BigEndian.Uint16(p[38:]))
	info.MC7Size = int(binary.BigEndian.Uint16(p[40:]))
	info.Author = plcText(p[42:50])
	info.Family = plcText(p[50:58])
	info.Header = plcText(p[58:66])
	info.Version = int(p[66])
	info.CheckSum = int(binary.BigEndian.Uint16(p[68:]))
	return info, nil
}

// siemensTimestamp helper get Siemens timestamp
func siemensTimestamp(EncodedDate int64) string {
	return time.Date(1984, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Second * time.Duration((EncodedDate * 86400))).Format("02.01.2006")
}
