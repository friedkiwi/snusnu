package server

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/friedkiwi/snusnu/sna/services/printer"
)

func TestGreenbarPDFIsReadable(t *testing.T) {
	pages, err := printer.RenderSCS([]byte{0xc1, 0xc2, 0xc3, 0x0c, 0xc4, 0xc5, 0xc6})
	if err != nil {
		t.Fatal(err)
	}
	pdf, err := renderGreenbarPDF(pages)
	if err != nil || !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) || !bytes.Contains(pdf, []byte("(ABC)")) || !bytes.Contains(pdf, []byte("(DEF)")) {
		t.Fatalf("PDF output: %v", err)
	}
	if _, err := exec.LookPath("pdfinfo"); err != nil {
		return
	}
	path := filepath.Join(t.TempDir(), "print.pdf")
	if err := os.WriteFile(path, pdf, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("pdfinfo", path).CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("Pages:           2")) {
		t.Fatalf("pdfinfo: %s: %v", output, err)
	}
}
