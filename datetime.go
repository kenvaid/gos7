package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

import (
	"fmt"
	"time"
)

// ClockClient supplies clearly named clock methods while preserving Client.
type ClockClient interface {
	GetPLCDateTime() (time.Time, error)
	SetPLCDateTime(time.Time) error
}

// Deprecated: historical PGClockWrite reads the clock. Use GetPLCDateTime.
func (mb *client) PGClockWrite() (time.Time, error) { return mb.GetPLCDateTime() }

// Deprecated: historical PGClockRead sets the clock. Use SetPLCDateTime.
func (mb *client) PGClockRead(value time.Time) error { return mb.SetPLCDateTime(value) }
func (mb *client) GetPLCDateTime() (time.Time, error) {
	request := NewProtocolDataUnit(append([]byte(nil), s7GetDatetimeTelegram...))
	response, err := mb.send(&request)
	if err != nil {
		return time.Time{}, err
	}
	_, payload, err := userDataPayload(response.Data)
	if err != nil {
		return time.Time{}, mb.badReply(response, err)
	}
	// GET may report 0x20 (Snap7) while SET requires the 0x19 marker.
	if len(payload) != 10 || payload[0] != 0 || (payload[1] != 0x19 && payload[1] != 0x20) {
		return time.Time{}, mb.badReply(response, fmt.Errorf("s7: invalid clock payload"))
	}
	value, err := (&Helper{}).GetDateTimeAtChecked(payload, 2)
	// Snap7 Server uses C's zero-based weekday in GET clock responses.
	// Accept that representation only when it matches the calendar date;
	// keep the public DATE_AND_TIME helper and SET encoding strict.
	if err != nil && payload[1] == 0x20 && payload[9]&15 <= 6 {
		clock := append([]byte(nil), payload[2:]...)
		clock[7]++
		value, err = (&Helper{}).GetDateTimeAtChecked(clock, 0)
	}
	if err != nil {
		return time.Time{}, mb.badReply(response, err)
	}
	return value, nil
}
func (mb *client) SetPLCDateTime(value time.Time) error {
	data := append([]byte(nil), s7SetDatetimeTelegram...)
	// Reserved byte at 29, mandatory 0x19 marker at 30, 8-byte DT at 31.
	if err := (&Helper{}).SetDateTimeAtChecked(data, 31, value); err != nil {
		return err
	}
	request := NewProtocolDataUnit(data)
	response, err := mb.send(&request)
	if err != nil {
		return err
	}
	if err := verifyUserDataAcknowledgement(response.Data); err != nil {
		return mb.badReply(response, err)
	}
	return nil
}
