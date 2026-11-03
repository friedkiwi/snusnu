package lu62

import "testing"

func TestStandaloneManagementSessionAcceptsAnyAuthorizedApplicationLU(t *testing.T) {
	s, err := NewStandaloneManagementSession("SOLNET.SNAB", "SNUSNU.PRINTER")
	if err != nil || s.Phase() != ManagementAwaitBind {
		t.Fatalf("printer management session: %v", err)
	}
	if _, err := NewStandaloneManagementSession("SOLNET.SNAB", "SOLNET.SNAB"); err == nil {
		t.Fatal("identical LU pair accepted")
	}
}
