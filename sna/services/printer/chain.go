package printer

import "errors"

// ErrChain means a FID3 request chain is out of order, changes identity, or
// exceeds the configured maximum size.
var ErrChain = errors.New("invalid 5494 FID3 request chain")

// ChainAssembler joins the RUs of one LU 4 or LU 7 FID3 request chain. Each
// D824 record carries one PIU, even when its RU is only part of a data stream.
// The caller owns outer LU 6.2 turn taking, sequence deduplication, and any
// response required after the completed chain has been durably processed.
type ChainAssembler struct {
	limit     int
	active    bool
	address   byte
	session   LU4Session
	expedited bool
	ru        []byte
}

func NewChainAssembler(maxBytes int) (*ChainAssembler, error) {
	if maxBytes <= 0 {
		return nil, ErrChain
	}
	return &ChainAssembler{limit: maxBytes}, nil
}

func (a *ChainAssembler) Active() bool { return a != nil && a.active }

func (a *ChainAssembler) Reset() {
	if a == nil {
		return
	}
	a.active = false
	a.ru = nil
}

// Feed returns a copied, complete RU only for an only-in-chain request or a
// last-in-chain request. It returns done=false for the first and middle PIUs.
// A rejected PIU discards any partial chain so a subsequent first PIU can
// start cleanly. It never sends an SNA response on the caller's behalf.
func (a *ChainAssembler) Feed(p LU4PIU) (ru []byte, done bool, err error) {
	if a == nil || a.limit <= 0 || p.Response || p.RH[0]&0x80 != 0 || len(p.RU) == 0 {
		if a != nil {
			a.Reset()
		}
		return nil, false, ErrChain
	}
	chain := p.RH[0] & 3
	if chain == 3 {
		if a.active || len(p.RU) > a.limit {
			a.Reset()
			return nil, false, ErrChain
		}
		return append([]byte(nil), p.RU...), true, nil
	}
	if chain == 2 {
		if a.active || len(p.RU) > a.limit {
			a.Reset()
			return nil, false, ErrChain
		}
		a.active = true
		a.address, a.session, a.expedited = p.Address, p.Session, p.Expedited
		a.ru = append([]byte(nil), p.RU...)
		return nil, false, nil
	}
	if !a.active || p.Address != a.address || p.Session != a.session || p.Expedited != a.expedited ||
		len(p.RU) > a.limit-len(a.ru) {
		a.Reset()
		return nil, false, ErrChain
	}
	a.ru = append(a.ru, p.RU...)
	if chain == 0 {
		return nil, false, nil
	}
	ru = a.ru
	a.Reset()
	return ru, true, nil
}
