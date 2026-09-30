package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.
import (
	"encoding/binary"
	"fmt"
)

func (mb *client) SetSessionPassword(password string) error {
	pwd := []byte{0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20}
	// Encodes the Password

	if len(password) > 8 {
		return fmt.Errorf("s7: password exceeds eight bytes")
	}
	copy(pwd, password)

	pwd[0] = byte(pwd[0] ^ 0x55)
	pwd[1] = byte(pwd[1] ^ 0x55)
	for c := 2; c < 8; c++ {
		pwd[c] = byte(pwd[c] ^ 0x55 ^ pwd[c-2])
	}
	requestData := make([]byte, len(s7SetPWDTelegram))
	//copy from telegram base
	copy(requestData, s7SetPWDTelegram)
	//copy from pwd set
	copy(requestData[29:29+8], pwd[0:8])

	request := NewProtocolDataUnit(requestData)
	//send
	response, err := mb.send(&request)
	if err == nil {
		err = verifySecurityResponse(response.Data)
		if err != nil {
			return mb.badReply(response, err)
		}
	}
	return err
}
func (mb *client) ClearSessionPassword() error {
	requestData := make([]byte, len(s7ClearPWDTelegram))
	//copy from telegram base
	copy(requestData, s7ClearPWDTelegram)
	request := ProtocolDataUnit{
		Data: requestData,
	}
	//send
	response, err := mb.send(&request)
	if err == nil {
		err = verifySecurityResponse(response.Data)
		if err != nil {
			return mb.badReply(response, err)
		}
	}
	return err

}

func (mb *client) GetProtection() (protection S7Protection, err error) {

	szl, _, err := mb.readSzl(0x0232, 0x0004)
	if err == nil {
		if len(szl.Data) < 12 {
			return protection, szl.fail(fmt.Errorf("s7: truncated protection record"))
		}
		protection.SchSchal = uint(binary.BigEndian.Uint16(szl.Data[2:]))
		protection.SchPar = uint(binary.BigEndian.Uint16(szl.Data[4:]))
		protection.SchRel = uint(binary.BigEndian.Uint16(szl.Data[6:]))
		protection.BartSch = uint(binary.BigEndian.Uint16(szl.Data[8:]))
		protection.AnlSch = uint(binary.BigEndian.Uint16(szl.Data[10:]))
	}
	return
}
func verifySecurityResponse(response []byte) (err error) {
	return verifyUserDataAcknowledgement(response)
}
