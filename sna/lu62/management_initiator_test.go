package lu62

import "testing"

func TestCandidateManagementBindCarriesSeparateCPAndLUIdentity(t *testing.T) {
	instance := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	token := [7]byte{0x23, 9, 10, 11, 12, 0x80, 0}
	request, err := CandidateManagementBind("SNUSNU.SVC", "SOLNET.PRTGUEST", 1, 2, instance, token)
	if err != nil {
		t.Fatal(err)
	}
	bind, err := ParseBind(request)
	if err != nil || bind == nil || !bind.Management || bind.PLU != "SNUSNU.SVC" || bind.SLU != "SOLNET.PRTGUEST" || bind.DAF != 1 || bind.OAF != 2 {
		t.Fatalf("management BIND: %+v %v", bind, err)
	}
	fqpcid, err := RequestFQPCID(request)
	if err != nil || len(fqpcid) == 0 {
		t.Fatalf("FQPCID: %x %v", fqpcid, err)
	}
	if _, err := CandidateManagementBind("SNUSNU.SVC", "SOLNET.PRTGUEST", 1, 2, [8]byte{}, token); err == nil {
		t.Fatal("accepted a reused zero instance")
	}
	bad := token
	bad[5] = 0
	if _, err := CandidateManagementBind("SNUSNU.SVC", "SOLNET.PRTGUEST", 1, 2, instance, bad); err == nil {
		t.Fatal("accepted a token without the V5R4 source marker")
	}
}

func TestFirst5494SourceManagementAddress(t *testing.T) {
	// IBM 5494 Release 3 assigns source LFSID 0200 first. In the BIND
	// direction T2.1 puts SIDL in DAF and SIDH in OAF.
	instance := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	token := [7]byte{0x23, 9, 10, 11, 12, 0x80, 0}
	request, err := CandidateManagementBind("SNUSNU.SVC", "SOLNET.S1054504", 0, 2, instance, token)
	if err != nil || len(request) < 9 || request[0] != 0x2f || request[2] != 0 || request[3] != 2 {
		t.Fatalf("first 5494 source BIND: %x %v", request, err)
	}
	if got := request[9 : 9+27]; len(got) != 27 || got[6] != 0xd0 || got[7] != 0xb3 || got[24] != 0x23 {
		t.Fatalf("5494 source BIND fixed section: %x", got)
	}
	bind, err := ParseBind(request)
	if err != nil || bind == nil || !bind.Management || bind.DAF != 0 || bind.OAF != 2 {
		t.Fatalf("first 5494 source BIND parsed: %+v %v", bind, err)
	}
}
