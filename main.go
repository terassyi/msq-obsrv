package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/spf13/cobra"
	"github.com/terassyi/msq-obsrv/pkg/bpf"
	"github.com/terassyi/msq-obsrv/pkg/conntrack"
	"github.com/terassyi/msq-obsrv/pkg/device"
	"github.com/vishvananda/netlink"
)

var rootCmd = cobra.Command{
	Use: "msq-obsrv",
	Run: Run,
}

var log *slog.Logger

var (
	upstream   string
	downstream string
)

func init() {
	rootCmd.Flags().StringVarP(&upstream, "upstream", "u", "eth0", "the interface to attach TC egress programs")
	rootCmd.Flags().StringVarP(&downstream, "downstream", "d", "eth.*", "the interface to attach TC ingress programs")

	log = slog.New(slog.NewJSONHandler(os.Stderr, nil))

}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}

func Run(cmd *cobra.Command, args []string) {
	if err := run(context.Background()); err != nil {
		log.Error("failed to run msq-obsrv", slog.Any("error", err))
		os.Exit(-1)
	}
}

func run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	defer func() {
		cancel()
	}()

	l, err := netlink.LinkByName(upstream)
	if err != nil {
		return err
	}

	ebpfObject, err := bpf.Load()
	if err != nil {
		return err
	}

	defer bpf.UnLoad()

	invSipReader, err := ringbuf.NewReader(ebpfObject.InvSip)
	if err != nil {
		return err
	}
	defer invSipReader.Close()

	downLinks, err := device.FindMatchedDevices(downstream)
	if err != nil {
		return err
	}

	attachedIngress := make([]link.Link, 0, len(downLinks))
	for _, l := range downLinks {
		log.InfoContext(ctx, "attach tcx ingress", slog.String("program", ebpfObject.TcIngress.String()), slog.String("device", l.Attrs().Name))
		ingress, err := link.AttachTCX(link.TCXOptions{
			Interface: l.Attrs().Index,
			Program:   ebpfObject.TcIngress,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			return err
		}
		attachedIngress = append(attachedIngress, ingress)

	}

	log.InfoContext(ctx, "attach tcx egress", slog.String("program", ebpfObject.TcEgress.String()), slog.String("device", upstream))
	egress, err := link.AttachTCX(link.TCXOptions{
		Interface: l.Attrs().Index,
		Program:   ebpfObject.TcEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return err
	}

	defer func() {
		for _, i := range attachedIngress {
			i.Close()
		}
		egress.Close()
	}()

	upstreamAddrVar := ebpfObject.UpstreamAddr
	// upstreamAddr := net.ParseIP(addr)
	// if upstreamAddr.To4() == nil {
	// 	return fmt.Errorf("invalid upstream addr: %v", addr)
	// }

	// get the IP address of the upstream link
	upstreamAddr, err := getUpstreamAddr(l)
	if err != nil {
		return err
	}
	n := ipToU32(upstreamAddr)

	log.InfoContext(ctx, "register the upstream address", slog.Any("address", upstreamAddr), slog.Any("address_u32", n))
	if err := upstreamAddrVar.Set(n); err != nil {
		return err
	}

	ct := conntrack.New(log)

	go func() {
		if err := ct.Run(ctx); err != nil {
			log.ErrorContext(ctx, "failed to run conntrack", slog.Any("error", err))
			cancel()
		}
	}()

	go func() {
		var evt bpf.MsqObsrvProgInvSipEvent
		for {
			record, err := invSipReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.ErrorContext(ctx, "received signal in ring buffer reader")
					return
				}
				log.ErrorContext(ctx, "failed to read event", slog.Any("error", err))
				continue
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
				log.ErrorContext(ctx, "failed to serialize event", slog.Any("error", err))
				continue
			}
			tuple, err := bpf.GetTupleFromEvent(&evt)
			if err != nil {
				log.ErrorContext(ctx, "failed to convert a tuple from event", slog.Any("error", err))
				continue
			}
			entry, err := ct.LookUp(tuple)
			if err != nil {
				if errors.Is(err, conntrack.ErrNoEntry) {
					log.WarnContext(ctx, "no such entry", slog.Any("tuple", tuple))
				} else {
					log.ErrorContext(ctx, "failed to get entries from tuple", slog.Any("error", err))
					continue
				}
			}
			log.InfoContext(ctx, "invalid source ip", slog.Any("entry", entry), slog.Any("invsip", uint32ToIP(evt.InvSip)))
		}
	}()

	<-ctrlC
	log.Info("got ctrl-c signal")
	time.Sleep(time.Second * 1)

	return nil
}

func ipToU32(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}
	return binary.LittleEndian.Uint32(ip)
}

func uint32ToIP(ipUint uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, ipUint)
	return ip
}

func getUpstreamAddr(l netlink.Link) (net.IP, error) {
	i, err := net.InterfaceByName(l.Attrs().Name)
	if err != nil {
		return nil, err
	}

	addr, err := i.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addr {
		s := strings.Split(a.String(), "/")
		if len(s) != 2 {
			continue
		}
		ip := net.ParseIP(s[0])
		if ip.To4() != nil {
			return ip, nil
		}
	}

	return nil, fmt.Errorf("no IP address found for interface %s", l.Attrs().Name)
}
