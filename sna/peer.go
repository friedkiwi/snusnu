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

func (p Peer) Valid() bool { return p.Principal != "" && p.NetID != "" && p.CP != "" && p.LU != "" }
