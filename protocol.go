package gos7

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	s7Job            = 1
	s7Ack            = 2
	s7AckData        = 3
	s7UserData       = 7
	minNegotiatedPDU = 240
)

type s7Message struct {
	kind         byte
	reference    uint16
	params, data []byte
	cpuError     uint16
}

func parseS7(packet []byte) (m s7Message, err error) {
	if len(packet) < 17 || packet[0] != 3 || packet[1] != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return m, fmt.Errorf("s7: invalid TPKT length or header")
	}
	if packet[4] != 2 || packet[5] != 0xf0 || packet[6] != 0x80 || packet[7] != 0x32 || packet[9] != 0 || packet[10] != 0 {
		return m, fmt.Errorf("s7: invalid COTP/S7 header")
	}
	m.kind, m.reference = packet[8], binary.BigEndian.Uint16(packet[11:13])
	header := 17
	switch m.kind {
	case s7Job, s7UserData:
	case s7Ack, s7AckData:
		header = 19
		if len(packet) < header {
			return m, fmt.Errorf("s7: truncated acknowledgement")
		}
		m.cpuError = binary.BigEndian.Uint16(packet[17:19])
	default:
		return m, fmt.Errorf("s7: unsupported message type %02x", m.kind)
	}
	parLen, dataLen := int(binary.BigEndian.Uint16(packet[13:15])), int(binary.BigEndian.Uint16(packet[15:17]))
	if header+parLen+dataLen != len(packet) {
		return m, fmt.Errorf("s7: parameter/data length mismatch")
	}
	m.params, m.data = packet[header:header+parLen], packet[header+parLen:]
	return m, nil
}

func verifyS7(request, response []byte) error {
	req, err := parseS7(request)
	if err != nil {
		return err
	}
	res, err := parseS7(response)
	if err != nil {
		return err
	}
	if req.reference != res.reference {
		return fmt.Errorf("s7: response reference mismatch")
	}
	switch req.kind {
	case s7Job:
		if res.kind != s7Ack && res.kind != s7AckData {
			return fmt.Errorf("s7: unexpected response type")
		}
		if res.cpuError != 0 {
			return nil
		}
		if len(req.params) == 0 || len(res.params) == 0 || req.params[0] != res.params[0] {
			return fmt.Errorf("s7: response function mismatch")
		}
	case s7UserData:
		if res.kind != s7UserData || len(req.params) < 8 || len(res.params) != 12 || !bytes.Equal(res.params[:3], []byte{0, 1, 0x12}) || res.params[3] != 8 || res.params[4] != 0x12 || res.params[5]>>4 != 8 || req.params[5]&15 != res.params[5]&15 || req.params[6] != res.params[6] {
			return fmt.Errorf("s7: invalid user-data response parameters")
		}
	default:
		return fmt.Errorf("s7: invalid request type")
	}
	return nil
}

func messageError(m s7Message) error {
	code := m.cpuError
	if m.kind == s7UserData {
		if len(m.params) != 12 {
			return fmt.Errorf("s7: truncated user-data parameters")
		}
		code = binary.BigEndian.Uint16(m.params[10:12])
	}
	if code != 0 {
		return &S7Error{High: byte(code >> 8), Low: byte(code)}
	}
	return nil
}

func userDataPayload(response []byte) ([]byte, []byte, error) {
	m, err := parseS7(response)
	if err != nil {
		return nil, nil, err
	}
	if m.kind != s7UserData {
		return nil, nil, fmt.Errorf("s7: expected user-data response")
	}
	if err := messageError(m); err != nil {
		return nil, nil, err
	}
	if len(m.data) < 4 || m.data[0] != 0xff || m.data[1] != tsResOctet || int(binary.BigEndian.Uint16(m.data[2:4])) != len(m.data)-4 {
		return nil, nil, fmt.Errorf("s7: invalid user-data payload")
	}
	return m.params, m.data[4:], nil
}

func dataLengthBytes(transport byte, length int) (int, error) {
	switch transport {
	case tsResBit:
		return (length + 7) / 8, nil
	case tsResByte, tsResInt:
		if length%8 != 0 {
			return 0, fmt.Errorf("s7: unaligned data length")
		}
		return length / 8, nil
	case 6, tsResReal, tsResOctet:
		return length, nil
	default:
		return 0, fmt.Errorf("s7: invalid data transport size %d", transport)
	}
}

// Only write acknowledgements may use the empty 0A/00/0000 form. Keep read
// payloads strict so "no data" can never become a successful read.
func verifyUserDataAcknowledgement(response []byte) error {
	m, err := parseS7(response)
	if err != nil {
		return err
	}
	if m.kind != s7UserData {
		return fmt.Errorf("s7: expected user-data acknowledgement")
	}
	if err := messageError(m); err != nil {
		return err
	}
	if !bytes.Equal(m.data, []byte{0xff, 9, 0, 0}) && !bytes.Equal(m.data, []byte{0x0a, 0, 0, 0}) {
		return fmt.Errorf("s7: invalid empty user-data acknowledgement")
	}
	return nil
}

func itemError(code byte) error {
	if code == 0xff {
		return nil
	}
	return fmt.Errorf("s7: item error %02x: %s", code, ErrorText(CPUError(uint(code))))
}

// PDUSizeProvider advertises the negotiated S7 PDU size, excluding TPKT/COTP.
// Custom transports without it use the conservative 240-byte size.
type PDUSizeProvider interface{ PDUSize() (int, error) }

// SessionTransporter optionally binds fault cleanup to the session that supplied
// a response. Its invalidate function must never close a newer session.
type SessionTransporter interface {
	SendWithSession(request []byte) (response []byte, invalidate func(), err error)
}

func (mb *client) pduSize() (int, error) {
	size := minNegotiatedPDU
	if provider, ok := mb.transporter.(PDUSizeProvider); ok {
		var err error
		size, err = provider.PDUSize()
		if err != nil {
			return 0, err
		}
	}
	if size < minNegotiatedPDU || size > 65528 {
		return 0, fmt.Errorf("s7: invalid negotiated PDU size %d", size)
	}
	return size, nil
}

func jobPacket(function byte, params, data []byte) []byte {
	p := make([]byte, 17+len(params)+len(data))
	p[0], p[4], p[5], p[6], p[7], p[8] = 3, 2, 0xf0, 0x80, 0x32, s7Job
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[13:15], uint16(len(params)))
	binary.BigEndian.PutUint16(p[15:17], uint16(len(data)))
	copy(p[17:], params)
	copy(p[17+len(params):], data)
	p[17] = function
	return p
}

func userDataRequest(params, data []byte) []byte {
	p := make([]byte, 17+len(params)+len(data))
	p[0], p[4], p[5], p[6], p[7], p[8] = 3, 2, 0xf0, 0x80, 0x32, s7UserData
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[13:15], uint16(len(params)))
	binary.BigEndian.PutUint16(p[15:17], uint16(len(data)))
	copy(p[17:], params)
	copy(p[17+len(params):], data)
	return p
}
