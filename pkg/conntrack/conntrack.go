package conntrack

import (
	"bytes"
	"context"
	"net"
	"os/exec"
	"sync"
)

/* TCP
$ conntrack -E
    [NEW] tcp      6 120 SYN_SENT src=10.0.1.1 dst=10.1.0.2 sport=42974 dport=8080 [UNREPLIED] src=10.1.0.2 dst=10.1.0.1 sport=8080 dport=42974
[DESTROY] tcp      6 120 CLOSE src=10.0.1.1 dst=10.1.0.2 sport=42974 dport=8080 [UNREPLIED] src=10.1.0.2 dst=10.1.0.1 sport=8080 dport=42974
    [NEW] tcp      6 120 SYN_SENT src=10.0.1.1 dst=10.1.0.2 sport=55958 dport=8080 [UNREPLIED] src=10.1.0.2 dst=10.1.0.1 sport=8080 dport=55958
 [UPDATE] tcp      6 60 SYN_RECV src=10.0.1.1 dst=10.1.0.2 sport=55958 dport=8080 src=10.1.0.2 dst=10.1.0.1 sport=8080 dport=55958
 [UPDATE] tcp      6 432000 ESTABLISHED src=10.0.1.1 dst=10.1.0.2 sport=55958 dport=8080 src=10.1.0.2 dst=10.1.0.1 sport=8080 dport=55958 [ASSURED]
 [UPDATE] tcp      6 120 FIN_WAIT src=10.0.1.1 dst=10.1.0.2 sport=55958 dport=8080 src=10.1.0.2 dst=10.1.0.1 sport=8080 dport=55958 [ASSURED]
 [UPDATE] tcp      6 30 LAST_ACK src=10.0.1.1 dst=10.1.0.2 sport=55958 dport=8080 src=10.1.0.2 dst=10.1.0.1 sport=8080 dport=55958 [ASSURED]
 [UPDATE] tcp      6 120 TIME_WAIT src=10.0.1.1 dst=10.1.0.2 sport=55958 dport=8080 src=10.1.0.2 dst=10.1.0.1 sport=8080 dport=55958 [ASSURED]
*/

/*
$ conntrack -E
    [NEW] udp      17 30 src=192.168.10.2 dst=192.168.10.1 sport=59916 dport=53 [UNREPLIED] src=192.168.10.1 dst=192.168.10.2 sport=53 dport=59916
 [UPDATE] udp      17 29 src=192.168.10.2 dst=192.168.10.1 sport=59916 dport=53 src=192.168.10.1 dst=192.168.10.2 sport=53 dport=59916
*/

type Conntrack struct {
	m       sync.Mutex
	entries map[uint32]Entry
}

func New() *Conntrack {
	return &Conntrack{
		m:       sync.Mutex{},
		entries: map[uint32]Entry{},
	}
}

func (c *Conntrack) Run(ctx context.Context) error {
	b := make([]byte, 1024*1024)
	buf := bytes.NewBuffer(b)
	cmd := exec.CommandContext(ctx, "conntrack", "-E")
	cmd.Stdout = buf
	return nil
}

type Entry struct {
	Protocol Protocol         `json:"protocol"`
	Events   map[Event]uint32 `json:"events"`
	TcpState TcpState         `json:"tcp_state,omitempty"`
	Original Tuple            `json:"original"`
	Reply    Tuple            `json:"reply"`
}

type Protocol uint8

const (
	ProtocolTcp Protocol = 0
	ProtocolUdp Protocol = 1
)

type Event uint8

const (
	EventNew     Event = 0
	EventUpdate  Event = 1
	EventDestroy Event = 2
)

type TcpState uint8

const (
	TcpStateNone        TcpState = 0
	TcpStateSynSent     TcpState = 1
	TcpStateSynRecv     TcpState = 2
	TcpStateEstablished TcpState = 3
	TcpStateFinWait     TcpState = 4
	TcpStateCloseWait   TcpState = 5
	TcpStateLastAck     TcpState = 6
	TcpStateTimeWait    TcpState = 7
	TcpStateClose       TcpState = 8
	TcpStateListen      TcpState = 9
)

type Tuple struct {
	SrcAddr net.IP `json:"src_addr"`
	DstAddr net.IP `json:"dst_addr"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
}
