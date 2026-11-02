package printer

import (
	"bytes"
	"testing"
)

func TestRenderPositionsAndPages(t *testing.T) {
	// IBM's SCS example: ABCD on line 4 and WXYZ at column 4 on line 5.
	data := []byte{
		0x2b, 0xc1, 0x06, 0x84, 0x01, 0x84, 0x05, 0x42,
		0x2b, 0xc2, 0x06, 0x42, 0x04, 0x42, 0x0a, 0x21,
		0x34, 0xc4, 0x04, 0xc1, 0xc2, 0xc3, 0xc4,
		0x34, 0x4c, 0x01, 0x34, 0xc0, 0x04,
		0xe6, 0xe7, 0xe8, 0xe9, 0x0c,
		0xc5, 0xd5, 0xc4,
	}
	pages, err := RenderSCS(data)
	if err != nil || len(pages) != 2 {
		t.Fatalf("render: %v, %d pages", err, len(pages))
	}
	first := pages[0].Lines()
	if len(first) != 5 || first[3] != "ABCD" || first[4] != "   WXYZ" || !bytes.Equal([]byte(pages[1].Lines()[0]), []byte("END")) {
		t.Fatalf("pages: %#v %#v", first, pages[1].Lines())
	}
}

func TestRejectTruncatedSCSOrder(t *testing.T) {
	for _, value := range [][]byte{{0x34, 0xc0}, {0x2b, 0xd2, 4, 1}, {0x03, 3, 'A'}} {
		if _, err := RenderSCS(value); err == nil {
			t.Fatalf("accepted %x", value)
		}
	}
}
