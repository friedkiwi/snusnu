// Package sna defines transport-neutral identity carried into local SNA
// services. An adapter must stamp these fields from its authenticated session
// and live route; application data cannot claim a different peer.
package sna

type Peer struct {
	Principal string
	NetID     string
	CP        string
	LU        string
}

func (p Peer) Valid() bool {
	return p.Principal != "" && validName(p.NetID) && validName(p.CP) && validName(p.LU)
}

func validName(value string) bool {
	if len(value) == 0 || len(value) > 8 {
		return false
	}
	for i := range value {
		c := value[i]
		if c >= 'A' && c <= 'Z' || c == '@' || c == '#' || c == '$' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}
