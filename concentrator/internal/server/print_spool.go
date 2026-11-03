package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/friedkiwi/snusnu/concentrator/internal/store"
	"github.com/friedkiwi/snusnu/sna/services/printer"
	"github.com/google/uuid"
)

// savePrintJob is called only after a printer conversation has accepted a
// complete job. The authenticated circuit source supplies the owner and SNA
// names; printer bytes never supply account ownership.
func (a *App) savePrintJob(ctx context.Context, peer LocalPeer, device, title string, scs []byte) (store.PrintJob, error) {
	if !peer.SNAPeer().Valid() || peer.RouterID == "" || len(scs) == 0 || len(scs) > printer.MaxJobBytes || !validRouterName(device) || len(device) > 32 {
		return store.PrintJob{}, errors.New("invalid print job source or data")
	}
	pages, err := printer.RenderSCS(scs)
	if err != nil {
		return store.PrintJob{}, fmt.Errorf("render SCS preview: %w", err)
	}
	if len(pages) == 0 {
		return store.PrintJob{}, errors.New("empty SCS preview")
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = "Print job"
	}
	if !validRouterName(title) {
		return store.PrintJob{}, errors.New("invalid print job title")
	}
	id := uuid.NewString()
	finalPath := filepath.Join(a.printDir, id+".scs")
	tempPath := filepath.Join(a.printDir, id+".tmp")
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return store.PrintJob{}, err
	}
	defer os.Remove(tempPath)
	if _, err = file.Write(scs); err != nil {
		file.Close()
		return store.PrintJob{}, err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return store.PrintJob{}, err
	}
	if err = file.Close(); err != nil {
		return store.PrintJob{}, err
	}
	if err = os.Rename(tempPath, finalPath); err != nil {
		return store.PrintJob{}, err
	}
	// The file contents are synced above. Persist the new directory entry before
	// committing a database row or acknowledging the print to its sender.
	dir, err := os.Open(a.printDir)
	if err != nil {
		os.Remove(finalPath)
		return store.PrintJob{}, err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(finalPath)
		return store.PrintJob{}, err
	}
	job := store.PrintJob{ID: id, OwnerID: peer.OwnerID, SourceRouterID: peer.RouterID, SourceNetID: peer.NetID, SourceCP: peer.CP, SourceLU: peer.LU, DeviceName: device, Title: title, ByteCount: int64(len(scs)), PageCount: int64(len(pages)), CreatedAt: store.Now()}
	if err = a.DB.InsertPrintJob(ctx, job); err != nil {
		os.Remove(finalPath)
		return store.PrintJob{}, err
	}
	return job, nil
}

func (a *App) readPrintJob(ctx context.Context, ownerID, id string) (store.PrintJob, []byte, error) {
	job, err := a.DB.PrintJobByID(ctx, ownerID, id)
	if err != nil {
		return store.PrintJob{}, nil, err
	}
	if _, err = uuid.Parse(job.ID); err != nil {
		return store.PrintJob{}, nil, store.ErrNotFound
	}
	file, err := os.Open(filepath.Join(a.printDir, job.ID+".scs"))
	if err != nil {
		return store.PrintJob{}, nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, printer.MaxJobBytes+1))
	if err != nil || len(data) != int(job.ByteCount) || len(data) > printer.MaxJobBytes {
		return store.PrintJob{}, nil, errors.New("stored print data is incomplete")
	}
	return job, data, nil
}
