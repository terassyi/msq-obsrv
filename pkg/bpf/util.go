package bpf

import (
	"encoding/binary"
	"net/netip"

	"github.com/terassyi/msq-obsrv/pkg/conntrack"
)

func GetTupleFromEvent(src *MsqObsrvProgInvSipEvent) (*conntrack.Tuple, error) {
	srcAddr := toNetipAddr(src.T.Saddr)
	dstAddr := toNetipAddr(src.T.Daddr)
	t := &conntrack.Tuple{
		SrcAddr: dstAddr, // reverse
		DstAddr: srcAddr,
		SrcPort: src.T.Dport,
		DstPort: src.T.Sport,
	}
	return t, nil
}

func toNetipAddr(n uint32) netip.Addr {
	b := [4]byte{}
	binary.LittleEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}
