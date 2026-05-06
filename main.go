package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	pcapdev "pcap2socks/internal/pcap"
	stackpkg "pcap2socks/internal/stack"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
)

func main() {
	var (
		source  = flag.String("s", "", "source IP or CIDR")
		dest    = flag.String("d", "", "upstream SOCKS5 server")
		ifName  = flag.String("i", "", "capture interface")
		mtuOpt  = flag.Uint("mtu", 0, "MTU override")
		dnsAddr = flag.String("dns", "", "UDP/53 relay target")
		verbose = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(newPrettyHandler(os.Stdout, level))
	slog.SetDefault(logger)
	// Route stdlib log (gvisor internals) through slog so the format stays consistent.
	log.SetFlags(0)
	log.SetOutput(slogWriter{})

	if *source == "" || *dest == "" {
		fmt.Fprintln(os.Stderr, "usage: pcap2socks -s SRC -d SOCKS5 [-i IFACE] [--mtu N] [--dns DNS] [-v]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	// --dns accepts either "host:port" or just "host" (port defaults to 53).
	if *dnsAddr != "" && !strings.Contains(*dnsAddr, ":") {
		*dnsAddr = *dnsAddr + ":53"
	}

	gwIP, network, err := parseSource(*source)
	if err != nil {
		fatal("parse -s: %v", err)
	}

	ifce, err := pickInterface(*ifName, gwIP)
	if err != nil {
		fatal("interface: %v", err)
	}
	if len(ifce.HardwareAddr) != 6 {
		fatal("interface %s has no usable MAC address", ifce.Name)
	}

	mtu := uint32(ifce.MTU)
	if *mtuOpt != 0 {
		mtu = uint32(*mtuOpt)
	}
	if mtu == 0 {
		mtu = 1500
	}

	slog.Info("starting",
		"interface", ifce.Name,
		"mac", ifce.HardwareAddr.String(),
		"gateway_ip", gwIP.String(),
		"network", network.String(),
		"socks5", *dest,
		"mtu", mtu,
	)
	printDeviceInstructions(network, gwIP, mtu)

	const nicID = tcpip.NICID(1)
	// stackRef is set after stack.Create returns. The pcap dispatch goroutine
	// can already call StackGetter (via learn()) before that, so we publish
	// the pointer atomically and the getter tolerates a nil load.
	var stackRef atomic.Pointer[stackpkg.NeighborStack]

	dev, err := pcapdev.Open(pcapdev.Config{
		Interface: *ifce,
		Network:   network,
		LocalIP:   gwIP,
		LocalMAC:  ifce.HardwareAddr,
		MTU:       mtu - ethernetOverhead(),
		NICID:     nicID,
		StackGetter: func() pcapdev.NeighborSetter {
			s := stackRef.Load()
			if s == nil {
				return nil
			}
			return s
		},
		VerboseARP: *verbose,
	})
	if err != nil {
		fatal("open pcap: %v", err)
	}
	defer dev.Close()

	ep, err := pcapdev.NewEndpoint(dev, mtu, ifce.HardwareAddr)
	if err != nil {
		fatal("create endpoint: %v", err)
	}

	s, err := stackpkg.Create(stackpkg.Config{
		LinkEndpoint: ethernet.New(ep),
		NICID:        nicID,
		SocksServer:  *dest,
		GatewayIP:    gwIP.String(),
		DNSRelay:     *dnsAddr,
	})
	if err != nil {
		fatal("create stack: %v", err)
	}
	stackRef.Store((*stackpkg.NeighborStack)(s))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	slog.Info("shutting down")
}

// parseSource accepts either:
//   - "192.168.1.0/24"  (CIDR; gateway = .1, or .2 if .1 is the network's first host... use .1)
//   - "192.168.1.10"    (single IP; treated as gateway, network derived as /24)
//   - "192.168.1.10/24" (single IP with explicit mask; gateway = the IP)
func parseSource(src string) (gw net.IP, network *net.IPNet, err error) {
	if !strings.Contains(src, "/") {
		ip := net.ParseIP(src)
		if ip == nil {
			return nil, nil, fmt.Errorf("not an IP or CIDR: %s", src)
		}
		v4 := ip.To4()
		if v4 == nil {
			return nil, nil, errors.New("only IPv4 supported")
		}
		// Default to /24 around the IP.
		_, n, _ := net.ParseCIDR(v4.String() + "/24")
		return v4, n, nil
	}
	ip, n, err := net.ParseCIDR(src)
	if err != nil {
		return nil, nil, err
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, nil, errors.New("only IPv4 supported")
	}
	// If the user gave a network address (host bits zero), pick .1 inside it as gateway.
	netIP := n.IP.To4()
	if netIP.Equal(v4) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(netIP)+1)
		v4 = net.IP(b[:])
	}
	if !n.Contains(v4) {
		return nil, nil, fmt.Errorf("derived gateway %s not in network %s", v4, n)
	}
	return v4, n, nil
}

// pickInterface returns the named interface, or auto-detects one whose IPv4
// matches gwIP's network (preferred) or otherwise the first usable interface.
func pickInterface(name string, gwIP net.IP) (*net.Interface, error) {
	if name != "" {
		ifce, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("by name %q: %w", name, err)
		}
		return ifce, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var candidates []net.Interface
	for _, ifce := range ifaces {
		if ifce.Flags&net.FlagUp == 0 || ifce.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(ifce.HardwareAddr) != 6 {
			continue
		}
		addrs, err := ifce.Addrs()
		if err != nil {
			continue
		}
		var hasV4 bool
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil || v4.IsLinkLocalUnicast() {
				continue
			}
			hasV4 = true
			if ipnet.Contains(gwIP) {
				return &ifce, nil
			}
		}
		if hasV4 {
			candidates = append(candidates, ifce)
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("no usable interface; pass -i")
	}
	if len(candidates) > 1 {
		var names []string
		for _, c := range candidates {
			names = append(names, c.Name)
		}
		return nil, fmt.Errorf("multiple candidate interfaces (%s); pass -i", strings.Join(names, ", "))
	}
	return &candidates[0], nil
}

func ethernetOverhead() uint32 { return 14 }

func printDeviceInstructions(network *net.IPNet, gw net.IP, mtu uint32) {
	start, end := usableHostRange(network, gw)
	mask := net.IP(network.Mask).String()
	rec := mtu - ethernetOverhead()
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Configure the source device with these settings:")
	fmt.Fprintln(os.Stderr, "----------------------------------------------------------")
	fmt.Fprintf(os.Stderr, "  IP Address:  %s - %s\n", start, end)
	fmt.Fprintf(os.Stderr, "  Subnet Mask: %s\n", mask)
	fmt.Fprintf(os.Stderr, "  Gateway:     %s\n", gw)
	fmt.Fprintf(os.Stderr, "  MTU:         %d (or lower)\n", rec)
	fmt.Fprintln(os.Stderr, "----------------------------------------------------------")
	fmt.Fprintln(os.Stderr, "")
}

func usableHostRange(n *net.IPNet, gw net.IP) (net.IP, net.IP) {
	netIP := n.IP.To4()
	ones, bits := n.Mask.Size()
	hostBits := uint32(bits - ones)
	first := binary.BigEndian.Uint32(netIP) + 1
	last := binary.BigEndian.Uint32(netIP) | ((1 << hostBits) - 1) - 1
	gwInt := binary.BigEndian.Uint32(gw.To4())
	if first == gwInt && last > first {
		first++
	} else if last == gwInt && last > first {
		last--
	}
	var s, e [4]byte
	binary.BigEndian.PutUint32(s[:], first)
	binary.BigEndian.PutUint32(e[:], last)
	return net.IP(s[:]), net.IP(e[:])
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pcap2socks: "+format+"\n", args...)
	os.Exit(1)
}
