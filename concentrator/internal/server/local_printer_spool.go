package server

import (
	"context"
	"errors"
	"io"
	"log"
	"os"

	"github.com/friedkiwi/snusnu/sna/services/printer"
)

// probePrinterSpool holds uncommitted printer output while the host still owns
// the printer turn. Each accepted chain is synced before its SNA response is
// sent. The probe treats CD as a candidate job boundary; a real 5494 writer
// trace must establish how consecutive spool files are separated.
type probePrinterSpool struct {
	file *os.File
	path string
	size int
}

func (s *probePrinterSpool) append(dir string, data []byte) error {
	if len(data) == 0 || len(data) > printer.MaxJobBytes-s.size {
		return errors.New("printer spool size limit exceeded")
	}
	if s.file == nil {
		file, err := os.CreateTemp(dir, "printer-probe-*.partial")
		if err != nil {
			return err
		}
		if err := file.Chmod(0600); err != nil {
			file.Close()
			os.Remove(file.Name())
			return err
		}
		parent, err := os.Open(dir)
		if err != nil {
			file.Close()
			os.Remove(file.Name())
			return err
		}
		err = parent.Sync()
		closeErr := parent.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			file.Close()
			os.Remove(file.Name())
			return err
		}
		s.file, s.path = file, file.Name()
	}
	n, err := s.file.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	s.size += len(data)
	return nil
}

func (s *probePrinterSpool) finish(ctx context.Context, a *App, source LocalPeer) error {
	if s.file == nil || s.size == 0 {
		return errors.New("empty printer spool")
	}
	if err := s.file.Close(); err != nil {
		return err
	}
	s.file = nil
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if len(data) != s.size {
		return errors.New("printer spool size changed")
	}
	job, err := a.savePrintJob(ctx, source, "SNUPRT01", "Print job", data)
	if err != nil {
		return err
	}
	log.Printf("printer probe spool stored: job=%s owner=%s source=%s.%s/%s bytes=%d pages=%d", job.ID, job.OwnerID, job.SourceNetID, job.SourceCP, job.SourceLU, job.ByteCount, job.PageCount)
	os.Remove(s.path)
	s.path, s.size = "", 0
	return nil
}

func (s *probePrinterSpool) close() {
	if s.file != nil {
		s.file.Close()
	}
	if s.path != "" {
		os.Remove(s.path)
	}
	*s = probePrinterSpool{}
}
