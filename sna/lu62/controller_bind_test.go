package lu62

import (
	"bytes"
	"testing"
)

func Test5494ControllerBindCandidate(t *testing.T) {
	pcid := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	request, err := Candidate5494ControllerBind("SNUSNU.PRINTER", "SOLNET.SNAB", "SNUSNU.SVC", 1, 2, 0x87, pcid)
	if err != nil {
		t.Fatal(err)
	}
	bind, err := ParseBind(request)
	if err != nil || bind == nil || bind.PLU != "SNUSNU.PRINTER" || bind.SLU != "SOLNET.SNAB" || bind.Mode != "QRMTWSC" || bind.DAF != 1 || bind.OAF != 2 {
		t.Fatalf("controller BIND: %+v %v", bind, err)
	}
	if !bytes.Equal(request[:9+27], append([]byte{0x2f, 0, 1, 2, 0, 0, 0x6b, 0x80, 0},
		[]byte{0x31, 0, 0x13, 7, 0xb0, 0xb0, 0xd0, 0xb3, 0, 0, 0x87, 0x87, 0x80, 0, 6, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0x23, 0, 0}...)) {
		t.Fatalf("unexpected IBM 5494 fixed BIND profile: %x", request[:9+27])
	}
	fq, err := RequestFQPCID(request)
	if err != nil || len(fq) != 11+len("SNUSNU.SVC") || !bytes.Equal(fq[2:10], pcid[:]) {
		t.Fatalf("FQPCID: %x %v", fq, err)
	}
	if _, err := Candidate5494ControllerBind("OTHER.PRINTER", "SOLNET.SNAB", "SNUSNU.SVC", 1, 2, 0x87, pcid); err == nil {
		t.Fatal("mismatched LU and CP NETIDs accepted")
	}
	if _, err := Candidate5494ControllerBind("SNUSNU.PRINTER", "SOLNET.SNAB", "SNUSNU.SVC", 1, 1, 0x87, pcid); err == nil {
		t.Fatal("identical FID2 addresses accepted")
	}
}

func TestQRMTWSCCNOSRequest(t *testing.T) {
	request := CNOS{Service: 2, SessionLimit: 57, SourceWinners: 56, TargetWinners: 1, Mode: "QRMTWSC", ModeWidth: 8}
	encoded, err := EncodeCNOS(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseCNOS(encoded)
	if err != nil || decoded != request {
		t.Fatalf("QRMTWSC CNOS: %+v %v, data=%x", decoded, err, encoded)
	}
	attach, err := CandidateCNOSAttach(1, 2, 1, request)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewCNOSResponder("QRMTWSC", 57)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := responder.AcceptAttach(attach); err != nil {
		t.Fatalf("CNOS Attach rejected by responder: %v", err)
	}
	request.TargetWinners = 2
	if _, err := EncodeCNOS(request); err == nil {
		t.Fatal("overcommitted session winners accepted")
	}
}
