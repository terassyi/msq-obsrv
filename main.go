package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/spf13/cobra"
	"github.com/terassyi/msq-obsrv/pkg/bpf"
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
	addr       string
	downstream string
)

func init() {
	rootCmd.Flags().StringVarP(&upstream, "upstream", "u", "eth0", "the interface to attach TC egress programs")
	rootCmd.Flags().StringVarP(&downstream, "downstream", "d", "eth.*", "the interface to attach TC ingress programs")
	rootCmd.Flags().StringVarP(&addr, "addr", "a", "127.0.0.1", "the address masqueraded")

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
	upstreamAddr := net.ParseIP(addr)
	if upstreamAddr.To4() == nil {
		return fmt.Errorf("invalid upstream addr: %v", addr)
	}

	n := ipToU32(upstreamAddr)

	log.InfoContext(ctx, "register the upstream address", slog.Any("address", upstreamAddr), slog.Any("address_u32", n))
	if err := upstreamAddrVar.Set(n); err != nil {
		return err
	}

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
