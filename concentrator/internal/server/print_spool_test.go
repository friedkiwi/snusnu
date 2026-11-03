package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
)

func TestPrintJobStorageUsesAuthenticatedOwner(t *testing.T) {
	a := testApp(t)
	owner, other := store.RandomUUID(), store.RandomUUID()
	for _, id := range []string{owner, other} {
		if _, err := a.DB.Exec(context.Background(), "INSERT INTO users(id,email,password_hash,role,verified_at,netid) VALUES(?,?,?,'user',?,?)", id, id+"@example.test", "unused", store.Now(), ""); err != nil {
			t.Fatal(err)
		}
	}
	source := LocalPeer{RouterID: store.RandomUUID(), OwnerID: owner, NetID: "PEERNET", CP: "HOST", LU: "PRT1"}
	raw := []byte{0x34, 0xc4, 1, 0xc1, 0xc2, 0xc3, 0x0c}
	job, err := a.savePrintJob(context.Background(), source, "SNUPRT01", "Guest report", raw)
	if err != nil {
		t.Fatal(err)
	}
	if job.OwnerID != owner || job.SourceNetID != "PEERNET" || job.SourceCP != "HOST" || job.SourceLU != "PRT1" || job.PageCount != 1 {
		t.Fatalf("job metadata: %+v", job)
	}
	stored, got, err := a.readPrintJob(context.Background(), owner, job.ID)
	if err != nil || stored.ID != job.ID || !bytes.Equal(got, raw) {
		t.Fatalf("stored job: %+v %x %v", stored, got, err)
	}
	if _, _, err := a.readPrintJob(context.Background(), other, job.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other owner read job: %v", err)
	}
	if _, err := os.Stat(filepath.Join(a.printDir, job.ID+".scs")); err != nil {
		t.Fatal(err)
	}
	jobs, err := a.DB.ListPrintJobs(context.Background(), owner, "report", 50, 0)
	if err != nil || len(jobs) != 1 || jobs[0].ID != job.ID {
		t.Fatalf("owner search: %+v %v", jobs, err)
	}
	jobs, err = a.DB.ListPrintJobs(context.Background(), other, "", 50, 0)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("other owner list: %+v %v", jobs, err)
	}
	ownerToken, _, err := a.DB.NewSession(context.Background(), owner, "full")
	if err != nil {
		t.Fatal(err)
	}
	otherToken, _, err := a.DB.NewSession(context.Background(), other, "full")
	if err != nil {
		t.Fatal(err)
	}
	ownerCookie := &http.Cookie{Name: "snusnu_session", Value: ownerToken}
	otherCookie := &http.Cookie{Name: "snusnu_session", Value: otherToken}
	list := uiGet(t, a, "/prints?q=report", ownerCookie)
	if list.Code != 200 || !strings.Contains(list.Body.String(), "Guest report") || !strings.Contains(list.Body.String(), "PEERNET.HOST / PRT1") {
		t.Fatalf("print list: %d %s", list.Code, list.Body.String())
	}
	preview := uiGet(t, a, "/prints/"+job.ID, ownerCookie)
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), "ABC") || !strings.Contains(preview.Body.String(), "Download greenbar PDF") {
		t.Fatalf("print preview: %d %s", preview.Code, preview.Body.String())
	}
	pdf := uiGet(t, a, "/prints/"+job.ID+"/pdf", ownerCookie)
	if pdf.Code != 200 || !bytes.HasPrefix(pdf.Body.Bytes(), []byte("%PDF-1.4")) {
		t.Fatalf("print PDF: %d %s", pdf.Code, pdf.Body.String())
	}
	for _, path := range []string{"/prints", "/prints/" + job.ID, "/prints/" + job.ID + "/pdf"} {
		response := uiGet(t, a, path, otherCookie)
		if strings.Contains(response.Body.String(), "Guest report") || strings.Contains(response.Body.String(), "ABC") || (path != "/prints" && response.Code != 404) {
			t.Fatalf("other owner path %s: %d %s", path, response.Code, response.Body.String())
		}
	}
}
