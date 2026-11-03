package server

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
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
}
