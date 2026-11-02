// Package lu62 provides conservative LU 6.2 session classification. It does
// not turn a decoded BIND into an accepted session without negotiation.
package lu62

import (
	"errors"
	"strings"

	"github.com/friedkiwi/snusnu/sna/piu"
)

var ErrBind = errors.New("invalid LU 6.2 BIND")
var ErrUnsupported = errors.New("unsupported LU 6.2 BIND")

type Bind struct {
	PLU, SLU, Mode string
	DAF, OAF       byte
	Management     bool
}

// ParseBind returns nil for other complete PIUs. Unknown cryptography and
// control-vector layouts are rejected rather than guessed.
func ParseBind(data []byte) (*Bind, error) {
	p, err := piu.ParseFID2(data)
	if err != nil {
		return nil, err
	}
	if p.RH[0]&0xe0 != 0x60 || len(p.RU) == 0 || p.RU[0] != 0x31 {
		return nil, nil
	}
	r := p.RU
	if len(r) < 28 || len(r) > 256 {
		return nil, ErrBind
	}
	if r[2] != 0x13 || r[3] != 0x07 || r[14] != 6 || r[15] != 2 || r[26] != 0 {
		return nil, ErrUnsupported
	}
	o := 27
	plu, next, err := nameAt(r, o, true)
	if err != nil {
		return nil, err
	}
	o = next
	if o >= len(r) {
		return nil, ErrBind
	}
	userLen := int(r[o])
	o++
	if o+userLen >= len(r) {
		return nil, ErrBind
	}
	end := o + userLen
	mode := ""
	if userLen > 0 {
		if r[o] != 0 {
			return nil, ErrUnsupported
		}
		o++
	}
	previous := byte(0)
	for o < end {
		n := int(r[o])
		if n < 1 || o+1+n > end {
			return nil, ErrBind
		}
		key := r[o+1]
		if key <= previous {
			return nil, ErrBind
		}
		previous = key
		if key == 2 {
			if n > 9 {
				return nil, ErrBind
			}
			mode, err = decodeName(r[o+2:o+1+n], false)
			if err != nil {
				return nil, err
			}
		}
		o += 1 + n
	}
	urcLen := int(r[end])
	if urcLen > 12 {
		return nil, ErrBind
	}
	slu, _, err := nameAt(r, end+1+urcLen, true)
	if err != nil {
		return nil, err
	}
	return &Bind{PLU: plu, SLU: slu, Mode: mode, DAF: p.TH[2], OAF: p.TH[3], Management: mode == "SNASVCMG" || mode == "CPSVCMG" || mode == "CPSVCMGR"}, nil
}

func nameAt(data []byte, offset int, dotted bool) (string, int, error) {
	if offset >= len(data) {
		return "", 0, ErrBind
	}
	n := int(data[offset])
	offset++
	if n < 1 || n > 17 || offset+n > len(data) {
		return "", 0, ErrBind
	}
	name, err := decodeName(data[offset:offset+n], dotted)
	return name, offset + n, err
}

func decodeName(data []byte, dotted bool) (string, error) {
	var b strings.Builder
	padding := false
	for _, x := range data {
		if x == 0x40 {
			padding = true
			continue
		}
		if padding {
			return "", ErrBind
		}
		var c byte
		switch {
		case x >= 0xc1 && x <= 0xc9:
			c = 'A' + x - 0xc1
		case x >= 0xd1 && x <= 0xd9:
			c = 'J' + x - 0xd1
		case x >= 0xe2 && x <= 0xe9:
			c = 'S' + x - 0xe2
		case x >= 0xf0 && x <= 0xf9:
			c = '0' + x - 0xf0
		case x == 0x4b && dotted:
			c = '.'
		case x == 0x7c:
			c = '@'
		case x == 0x7b:
			c = '#'
		case x == 0x5b:
			c = '$'
		default:
			return "", ErrBind
		}
		b.WriteByte(c)
	}
	name := b.String()
	if dotted {
		parts := strings.Split(name, ".")
		if len(parts) > 2 {
			return "", ErrBind
		}
		for _, part := range parts {
			if len(part) == 0 || len(part) > 8 {
				return "", ErrBind
			}
		}
	}
	return name, nil
}
