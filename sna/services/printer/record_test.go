package printer

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRFC2877PrintAndEnd(t *testing.T) {
	// RFC 2877 sections 10.1-10.3: first print data, null print, response.
	first, err := hex.DecodeString("001312a001010a18000100000000000034c401")
	if err != nil {
		t.Fatal(err)
	}
	record, err := ParseRecord(first)
	if err != nil || record.Flow != FlowPrint || record.Flags != 0x1800 || record.Operation != OpPrint || !bytes.Equal(record.Data, []byte{0x34, 0xc4, 1}) {
		t.Fatalf("print record: %+v, %v", record, err)
	}
	var job Job
	if done, err := job.Add(record); done || err != nil {
		t.Fatalf("first record: %t, %v", done, err)
	}
	last, _ := hex.DecodeString("001112a001010a08000100000000000000")
	record, err = ParseRecord(last)
	if err != nil {
		t.Fatal(err)
	}
	if done, err := job.Add(record); !done || err != nil || !job.Closed() {
		t.Fatalf("last record: %t, %v", done, err)
	}
	if !bytes.Equal(job.Bytes(), []byte{0x34, 0xc4, 1}) {
		t.Fatalf("wrong SCS: %x", job.Bytes())
	}
	response, err := ParseRecord(CompleteResponse())
	if err != nil || response.Flow != FlowResponse || response.Operation != OpPrint || len(response.Data) != 0 {
		t.Fatalf("completion: %+v, %v", response, err)
	}
}

func TestRejectMalformedRecord(t *testing.T) {
	for _, input := range [][]byte{
		{}, {0, 10, 0x12, 0xa0, 1, 2, 4, 0, 0},
		{0, 10, 0x12, 0xa1, 1, 2, 4, 0, 0, 1},
		{0, 10, 0x12, 0xa0, 1, 2, 9, 0, 0, 1},
	} {
		if _, err := ParseRecord(input); err == nil {
			t.Fatalf("accepted %x", input)
		}
	}
}
