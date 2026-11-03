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
