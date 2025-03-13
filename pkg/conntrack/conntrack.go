package conntrack

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
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

var ErrNoEntry error = errors.New("no conntrack entry in cache")

type Conntrack struct {
	m       sync.Mutex
	entries map[Tuple]*Entry // key is tuple that is masqueraded
	logger  *slog.Logger
}

func New(logger *slog.Logger) *Conntrack {
	return &Conntrack{
		m:       sync.Mutex{},
		entries: make(map[Tuple]*Entry),
		logger:  logger,
	}
}

func (c *Conntrack) LookUp(t *Tuple) (*Entry, error) {
	c.m.Lock()
	defer c.m.Unlock()

	entry, ok := c.entries[*t]
	if !ok {
		return nil, ErrNoEntry
	}
	return entry, nil
}

func (c *Conntrack) Dump() map[Tuple]*Entry {
	c.m.Lock()
	defer c.m.Unlock()
	m := map[Tuple]*Entry{}
	for k, v := range c.entries {
		m[k] = v
	}
	return m
}

func (c *Conntrack) Run(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "conntrack", "-E", "--protonum", "tcp")

	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(out)

	c.logger.InfoContext(ctx, "start to execute conntrack -E --protonum tcp")
	go func(ctx context.Context) {
		if err := cmd.Run(); err != nil {
			c.logger.ErrorContext(ctx, "failed to run conntrack command", slog.Any("error", err))
		}
	}(ctx)

	for scanner.Scan() {
		line := scanner.Text()
		entry, err := parseConntrackEntry(line)
		if err != nil {
			return err
		}
		key := *entry.Reply

		_, err = c.insert(key, entry)
		if err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (c *Conntrack) insert(key Tuple, value *Entry) (*Entry, error) {
	c.m.Lock()
	defer c.m.Unlock()
	e, ok := c.entries[key]
	if !ok {
		c.entries[key] = value
	} else {
		e.TcpState = value.TcpState
		for k, v := range value.Events {
			if ee, ok := e.Events[k]; !ok {
				e.Events[k] = v
			} else {
				ee += v
			}
		}
	}

	return e, nil
}

type Entry struct {
	Protocol Protocol         `json:"protocol"`
	Events   map[Event]uint32 `json:"events"`
	TcpState TcpState         `json:"tcp_state,omitempty"`
	Original *Tuple           `json:"original"`
	Reply    *Tuple           `json:"reply"`
}

func newEntry(protocol Protocol) *Entry {
	return &Entry{
		Protocol: protocol,
		Events:   make(map[Event]uint32),
	}
}

func parseConntrackEntry(line string) (*Entry, error) {
	elms := strings.Fields(line)
	if len(elms) == 0 {
		return nil, io.EOF
	}

	protocol := parseProtocol(elms[1])
	entry := newEntry(protocol)

	event := parseEvent(elms[0])
	eventCount, ok := entry.Events[event]
	if ok {
		eventCount++
	} else {
		entry.Events[event] = 1
	}

	err := func() error {
		switch event {
		case EventNew:
			entry.TcpState = parseTcpState(elms[4])
			var err error
			entry.Original, err = parseTuple(elms[5:9])
			if err != nil {
				return err
			}
			entry.Reply, err = parseTuple(elms[10:14])
			if err != nil {
				return err
			}
		case EventUpdate:
			entry.TcpState = parseTcpState(elms[4])
			var err error
			entry.Original, err = parseTuple(elms[5:9])
			if err != nil {
				return err
			}
			entry.Reply, err = parseTuple(elms[9:13])
			if err != nil {
				return err
			}
		case EventDestroy:
			if _, err := strconv.Atoi(elms[3]); err != nil {
				entry.TcpState = parseTcpState(elms[3])
				var err error
				entry.Original, err = parseTuple(elms[4:8])
				if err != nil {
					return err
				}
				if len(strings.Split(elms[8], "=")) == 2 {
					entry.Reply, err = parseTuple(elms[8:12])
					if err != nil {
						return err
					}
				} else {
					entry.Reply, err = parseTuple(elms[9:13])
					if err != nil {
						return err
					}
				}
			} else {
				entry.TcpState = parseTcpState(elms[4])
				var err error
				entry.Original, err = parseTuple(elms[5:9])
				if err != nil {
					return err
				}
				if len(strings.Split(elms[9], "=")) == 2 {
					entry.Reply, err = parseTuple(elms[9:13])
					if err != nil {
						return err
					}
				} else {
					entry.Reply, err = parseTuple(elms[10:14])
					if err != nil {
						return err
					}
				}
			}
		default:
			return fmt.Errorf("unknown event: %v", event)
		}
		return nil
	}()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, line)
	}

	return entry, nil
}

type Protocol uint8

const (
	ProtocolTcp     Protocol = 0
	ProtocolUdp     Protocol = 1
	ProtocolUnknown Protocol = 1
)

func (p Protocol) String() string {
	switch p {
	case ProtocolTcp:
		return "TCP"
	case ProtocolUdp:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

// elm[1]
func parseProtocol(elm string) Protocol {
	switch elm {
	case "tcp":
		return ProtocolTcp
	case "udp":
		return ProtocolUdp
	default:
		return ProtocolUnknown
	}
}

type Event uint8

const (
	EventNew     Event = 0
	EventUpdate  Event = 1
	EventDestroy Event = 2
	EventUnknown Event = 3
)

func (e Event) String() string {
	switch e {
	case EventNew:
		return "NEW"
	case EventUpdate:
		return "UPDATE"
	case EventDestroy:
		return "DESTROY"
	default:
		return "UNKNOWN"
	}
}

// elm[0]
func parseEvent(elm string) Event {
	t := strings.TrimPrefix(elm, "[")
	t = strings.TrimSuffix(t, "]")

	switch t {
	case "NEW":
		return EventNew
	case "DESTROY":
		return EventDestroy
	case "UPDATE":
		return EventUpdate
	default:
		return EventUnknown
	}
}

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

func (s TcpState) String() string {
	switch s {
	case TcpStateSynSent:
		return "SYN_SENT"
	case TcpStateSynRecv:
		return "SYN_RECV"
	case TcpStateEstablished:
		return "ESTABLISHED"
	case TcpStateFinWait:
		return "FIN_WAIT"
	case TcpStateCloseWait:
		return "CLOSE_WAIT"
	case TcpStateLastAck:
		return "LAST_ACK"
	case TcpStateTimeWait:
		return "TIME_WAIT"
	case TcpStateClose:
		return "CLOSE"
	case TcpStateListen:
		return "LISTEN"
	default:
		return "NONE"
	}
}

// if tcp
// elm[4]
func parseTcpState(elm string) TcpState {
	switch elm {
	case "SYN_SENT":
		return TcpStateSynSent
	case "SYN_RECV":
		return TcpStateSynRecv
	case "ESTABLISHED":
		return TcpStateEstablished
	case "FIN_WAIT":
		return TcpStateFinWait
	case "CLOSE_WAIT":
		return TcpStateCloseWait
	case "LAST_ACK":
		return TcpStateLastAck
	case "TIME_WAIT":
		return TcpStateTimeWait
	case "CLOSE":
		return TcpStateClose
	case "LISTEN":
		return TcpStateListen
	default:
		return TcpStateNone
	}
}

type Tuple struct {
	SrcAddr netip.Addr `json:"src_addr"`
	DstAddr netip.Addr `json:"dst_addr"`
	SrcPort uint16     `json:"src_port"`
	DstPort uint16     `json:"dst_port"`
}

const (
	srcAddrPrefix = "src="
	dstAddrPrefix = "dst="
	srcPortPrefix = "sport="
	dstPortPrefix = "dport="
)

func (t *Tuple) Equal(d *Tuple) bool {
	if t.SrcAddr != d.SrcAddr || t.DstAddr != d.DstAddr || t.SrcPort != d.SrcPort || t.DstPort != d.DstPort {
		return false
	}
	return true
}

func parseTuple(elms []string) (*Tuple, error) {
	if len(elms) != 4 {
		return nil, fmt.Errorf("invalid tuple elements: %v", elms)
	}
	tuple := &Tuple{}

	var err error
	tuple.SrcAddr, err = netip.ParseAddr(strings.Replace(elms[0], srcAddrPrefix, "", -1))
	if err != nil {
		return nil, err
	}
	tuple.DstAddr, err = netip.ParseAddr(strings.Replace(elms[1], dstAddrPrefix, "", -1))
	if err != nil {
		return nil, err
	}

	sport, err := strconv.Atoi(strings.Replace(elms[2], srcPortPrefix, "", -1))
	if err != nil {
		return nil, err
	}
	tuple.SrcPort = uint16(sport)

	dport, err := strconv.Atoi(strings.Replace(elms[3], dstPortPrefix, "", -1))
	if err != nil {
		return nil, err
	}
	tuple.DstPort = uint16(dport)

	return tuple, nil
}
