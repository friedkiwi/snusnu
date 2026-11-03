package printer

import (
	"errors"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

var ErrSCS = errors.New("unsupported or malformed SCS print stream")

const Columns = 132
const Rows = 66
const MaxPages = 1000
const MaxJobBytes = 32 << 20

// Page is a fixed-pitch image of one SCS page. Unused trailing cells and
// lines are omitted when Lines is called.
type Page struct{ cells [Rows][Columns]rune }

func (p Page) Lines() []string {
	last := -1
	lines := make([]string, Rows)
	for row, cells := range p.cells {
		end := Columns
		for end > 0 && cells[end-1] == 0 {
			end--
		}
		if end != 0 {
			last = row
		}
		var b strings.Builder
		for _, cell := range cells[:end] {
			if cell == 0 {
				b.WriteByte(' ')
			} else {
				b.WriteRune(cell)
			}
		}
		lines[row] = b.String()
	}
	if last < 0 {
		return nil
	}
	return lines[:last+1]
}

// RenderSCS renders fixed-pitch text and presentation-position orders. It
// consumes multibyte device-format orders without reproducing font, forms,
// or graphics effects. Callers should retain the raw stream alongside this
// text preview.
func RenderSCS(data []byte) ([]Page, error) {
	pages := []Page{{}}
	row, col := 0, 0
	newPage := func() error {
		if len(pages) >= MaxPages {
			return ErrSCS
		}
		pages = append(pages, Page{})
		row, col = 0, 0
		return nil
	}
	for i := 0; i < len(data); {
		b := data[i]
		i++
		switch b {
		case 0x00: // Null padding.
		case 0x0c: // Form feed.
			if err := newPage(); err != nil {
				return nil, err
			}
		case 0x0d: // Carriage return.
			col = 0
		case 0x15, 0x25: // New line and line feed.
			row++
			if b == 0x15 {
				col = 0
			}
			if row >= Rows {
				if err := newPage(); err != nil {
					return nil, err
				}
			}
		case 0x03: // ASCII transparency: length followed by raw bytes.
			if i >= len(data) || i+1+int(data[i]) > len(data) {
				return nil, ErrSCS
			}
			n := int(data[i])
			i++
			for _, raw := range data[i : i+n] {
				if raw == '\r' || raw == '\n' || raw == '\f' {
					return nil, ErrSCS
				}
				if raw >= 0x20 && raw < 0x7f && col < Columns {
					pages[len(pages)-1].cells[row][col] = rune(raw)
					col++
				}
			}
			i += n
		case 0x2b: // Multibyte control; length includes its own byte.
			if i+2 > len(data) || data[i+1] == 0 || i+1+int(data[i+1]) > len(data) {
				return nil, ErrSCS
			}
			i += 1 + int(data[i+1])
		case 0x34: // Presentation position, one-based row/column.
			if i+2 > len(data) {
				return nil, ErrSCS
			}
			kind, position := data[i], int(data[i+1])
			i += 2
			switch kind {
			case 0xc0:
				col = position - 1
			case 0xc4:
				row = position - 1
			case 0xc8:
				col += position
			case 0x4c:
				row += position
			default:
				return nil, ErrSCS
			}
			if row < 0 || row >= Rows || col < 0 || col >= Columns {
				return nil, ErrSCS
			}
		default:
			if b < 0x40 || col >= Columns {
				return nil, ErrSCS
			}
			pages[len(pages)-1].cells[row][col] = charmap.CodePage037.DecodeByte(b)
			col++
		}
	}
	if len(pages) > 1 && len(pages[len(pages)-1].Lines()) == 0 {
		pages = pages[:len(pages)-1]
	}
	return pages, nil
}
