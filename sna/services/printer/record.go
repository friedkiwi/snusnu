// Package printer parses SCS and the 5250 printer pass-through records
// described by RFC 4777. A 5494 uses additional LU 6.2 controller and
// device-session protocols; this package does not implement those sessions.
package printer

import (
	"encoding/binary"
	"errors"
)

var ErrRecord = errors.New("invalid 5250 printer record")

// Record is one complete GDS X'12A0' printer record. Data is a copy and can
// be retained after the caller reuses its input buffer.
type Record struct {
	Flow      uint16
	Flags     uint16
	Operation byte
	Data      []byte
}

const (
	FlowPrint    = 0x0101
	FlowResponse = 0x0102
	OpPrint      = 0x01
)

// ParseRecord validates the steady-state 5250 printer header documented in
// RFC 4777 section 11. It accepts one record, not an arbitrary byte stream.
func ParseRecord(gds []byte) (Record, error) {
	if len(gds) < 10 || len(gds) > 65535 || int(binary.BigEndian.Uint16(gds[:2])) != len(gds) ||
		gds[2] != 0x12 || gds[3] != 0xa0 {
		return Record{}, ErrRecord
	}
	flow := binary.BigEndian.Uint16(gds[4:6])
	headerLen := int(gds[6])
	if headerLen < 4 || 6+headerLen > len(gds) || (flow != FlowPrint && flow != FlowResponse) {
		return Record{}, ErrRecord
	}
	if flow == FlowResponse && (headerLen != 4 || len(gds) != 10) {
		return Record{}, ErrRecord
	}
	return Record{
		Flow: flow, Flags: binary.BigEndian.Uint16(gds[7:9]), Operation: gds[9],
		Data: append([]byte(nil), gds[6+headerLen:]...),
	}, nil
}

// CompleteResponse acknowledges one printed record. The caller must send it
// only after the corresponding data has been durably accepted.
func CompleteResponse() []byte {
	return []byte{0, 10, 0x12, 0xa0, 1, 2, 4, 0, 0, OpPrint}
}

// Job collects one bounded print stream, preserving raw SCS for a renderer.
// A final null print record closes the job. One conversation may contain
// multiple jobs.
type Job struct {
	data   []byte
	closed bool
}

const MaxJobBytes = 32 << 20

func (j *Job) Add(record Record) (done bool, err error) {
	if j.closed || record.Flow != FlowPrint || record.Operation != OpPrint {
		return false, ErrRecord
	}
	if len(record.Data) == 0 || (len(record.Data) == 1 && record.Data[0] == 0) {
		if record.Flags&0x0800 == 0 || len(j.data) == 0 {
			return false, ErrRecord
		}
		j.closed = true
		return true, nil
	}
	if len(j.data)+len(record.Data) > MaxJobBytes {
		return false, ErrRecord
	}
	j.data = append(j.data, record.Data...)
	return false, nil
}

func (j *Job) Bytes() []byte { return append([]byte(nil), j.data...) }
func (j *Job) Closed() bool  { return j.closed }
