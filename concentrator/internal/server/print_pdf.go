package server

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/friedkiwi/snusnu/sna/services/printer"
	"golang.org/x/text/encoding/charmap"
)

// renderGreenbarPDF writes a fixed-pitch, 132-column landscape page. PDF
// drawing belongs to the portal; the reusable SNA printer package supplies
// the device-neutral page image.
func renderGreenbarPDF(pages []printer.Page) ([]byte, error) {
	if len(pages) == 0 || len(pages) > printer.MaxPages {
		return nil, printer.ErrSCS
	}
	const width, height = 1224, 792 // US ledger landscape
	objects := []string{"", "<< /Type /Catalog /Pages 2 0 R >>", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"}
	var kids strings.Builder
	for _, page := range pages {
		var stream strings.Builder
		stream.WriteString("0.97 0.985 0.94 rg 0 0 1224 792 re f\n")
		for row := 0; row < printer.Rows; row++ {
			if row%2 == 0 {
				fmt.Fprintf(&stream, "0.87 0.93 0.82 rg 30 %d 1164 10 re f\n", 735-row*10)
			}
		}
		stream.WriteString("0 0 0 rg BT /F1 7 Tf\n")
		for row, line := range page.Lines() {
			encoded, err := charmap.Windows1252.NewEncoder().Bytes([]byte(line))
			if err != nil {
				encoded = []byte(strings.ToValidUTF8(line, "?"))
				for i := range encoded {
					if encoded[i] >= 0x80 {
						encoded[i] = '?'
					}
				}
			}
			fmt.Fprintf(&stream, "1 0 0 1 35 %d Tm (%s) Tj\n", 737-row*10, escapePDFText(encoded))
		}
		stream.WriteString("ET\n")
		pageID := len(objects)
		contentID := pageID + 1
		objects = append(objects, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", width, height, contentID))
		body := stream.String()
		objects = append(objects, fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(body), body))
		fmt.Fprintf(&kids, "%d 0 R ", pageID)
	}
	objects[2] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), len(pages))
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for i := 1; i < len(objects); i++ {
		offsets[i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i, objects[i])
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects))
	for i := 1; i < len(objects); i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects), xref)
	return out.Bytes(), nil
}

func escapePDFText(value []byte) string {
	var out strings.Builder
	for _, b := range value {
		switch b {
		case '(', ')', '\\':
			out.WriteByte('\\')
			out.WriteByte(b)
		default:
			if b < 32 || b == 127 {
				out.WriteByte('?')
			} else {
				out.WriteByte(b)
			}
		}
	}
	return out.String()
}
