package pcap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/gopacket/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// NeighborSetter is the subset of *stack.Stack we need to teach gvisor about
// learned device IP→MAC pairs (so it knows where to send replies even if the
// device ignored our gratuitous ARP).
type NeighborSetter interface {
	AddStaticNeighbor(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address, linkAddr tcpip.LinkAddress) tcpip.Error
}

// Config configures a pcap-based gateway device.
type Config struct {
	// Interface is the host interface to capture on.
	Interface net.Interface
	// Network is the LAN CIDR we're acting as gateway for. Only frames whose
	// source IP falls in this network are forwarded into the stack.
	Network *net.IPNet
	// LocalIP is the gateway IP we own (clients should set this as their gateway).
	LocalIP net.IP
	// LocalMAC is the MAC we advertise for LocalIP.
	LocalMAC net.HardwareAddr
	// MTU advertised to the stack. Must be > 0.
	MTU uint32
	// NICID identifies the gvisor NIC we're bound to (used for AddStaticNeighbor).
	NICID tcpip.NICID
	// Stack receives learned neighbors (lazily, via the StackGetter).
	StackGetter func() NeighborSetter
	// VerboseARP widens the BPF filter to also capture ARP requests originating
	// outside the configured CIDR (still only those targeting our gateway IP),
	// so that DEBUG can log them. Off by default to keep the kernel filter tight.
	VerboseARP bool
}

// Device wraps a libpcap handle and implements ReadWriter for the iobased
// endpoint. It also handles ARP requests inline (replies straight back via
// pcap, never propagated up to the stack) and learns IP→MAC pairs.
type Device struct {
	cfg Config

	handle *pcap.Handle
	rmu    sync.Mutex
	closed atomic.Bool

	mu       sync.Mutex
	ipMACTab map[string]net.HardwareAddr
}

// Open creates the pcap handle, sets the BPF filter, sends a gratuitous ARP,
// and returns a ready-to-use Device.
func Open(cfg Config) (*Device, error) {
	if cfg.Network == nil || cfg.LocalIP == nil || len(cfg.LocalMAC) == 0 || cfg.MTU == 0 {
		return nil, fmt.Errorf("pcap.Open: incomplete config")
	}
	pcapDev, err := findPcapDevice(cfg.Interface)
	if err != nil {
		return nil, err
	}

	inactive, err := pcap.NewInactiveHandle(pcapDev.Name)
	if err != nil {
		return nil, fmt.Errorf("pcap: new inactive handle: %w", err)
	}
	defer inactive.CleanUp()

	for _, step := range []struct {
		name string
		fn   func() error
	}{
		{"promisc", func() error { return inactive.SetPromisc(true) }},
		{"snaplen", func() error { return inactive.SetSnapLen(1600) }},
		{"timeout", func() error { return inactive.SetTimeout(pcap.BlockForever) }},
		{"immediate", func() error { return inactive.SetImmediateMode(true) }},
		{"buffer", func() error { return inactive.SetBufferSize(512 * 1024) }},
	} {
		if err := step.fn(); err != nil {
			return nil, fmt.Errorf("pcap: %s: %w", step.name, err)
		}
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("pcap: activate: %w", err)
	}

	// BPF: capture ARP requests targeting us (but not from us), and IPv4
	// from inside our LAN bound for outside (and not our own ICMP — loop
	// prevention in promiscuous mode). When VerboseARP is on, drop the
	// "arp src net <cidr>" constraint so DEBUG can see ARP from outside our
	// CIDR too (these are ignored by the handler, only logged).
	var arpClause string
	if cfg.VerboseARP {
		arpClause = fmt.Sprintf("(arp dst host %s and not arp src host %s)", cfg.LocalIP, cfg.LocalIP)
	} else {
		arpClause = fmt.Sprintf("(arp dst host %s and arp src net %s and not arp src host %s)",
			cfg.LocalIP, cfg.Network, cfg.LocalIP)
	}
	bpf := fmt.Sprintf(
		"%s or (src net %s and not dst net %s and not (icmp and src host %s))",
		arpClause, cfg.Network, cfg.Network, cfg.LocalIP,
	)
	if err := handle.SetBPFFilter(bpf); err != nil {
		handle.Close()
		return nil, fmt.Errorf("pcap: set bpf: %w", err)
	}

	d := &Device{
		cfg:      cfg,
		handle:   handle,
		ipMACTab: make(map[string]net.HardwareAddr),
	}

	// Announce ourselves so devices update their ARP caches immediately.
	if frame, err := BuildGratuitousARP(cfg.LocalIP, cfg.LocalMAC); err == nil {
		if werr := handle.WritePacketData(frame); werr != nil {
			slog.Warn("pcap: gratuitous arp write failed", "err", werr)
		} else {
			slog.Info("arp: gratuitous broadcast", "ip", cfg.LocalIP.String(), "mac", cfg.LocalMAC.String())
		}
	}

	return d, nil
}

// Close releases the underlying pcap handle.
func (d *Device) Close() {
	if d.closed.Swap(true) {
		return
	}
	if d.handle != nil {
		d.handle.Close()
	}
}

// Read returns the next ethernet frame to feed into the stack. It transparently
// answers ARP requests directed at us (writing the reply via pcap) and returns
// nil for any frame that should not be propagated to the stack — the caller's
// loop already handles nil by continuing.
func (d *Device) Read() []byte {
	d.rmu.Lock()
	defer d.rmu.Unlock()

	for {
		if d.closed.Load() {
			return nil
		}
		data, _, err := d.handle.ZeroCopyReadPacketData()
		if err != nil {
			if d.closed.Load() || errors.Is(err, io.EOF) || errors.Is(err, pcap.NextErrorNotActivated) {
				return nil
			}
			slog.Error("pcap: read packet", "err", err)
			return nil
		}
		if len(data) < ethHeaderLen {
			continue
		}
		eth := header.Ethernet(data)
		switch eth.Type() {
		case header.IPv4ProtocolNumber:
			ip := header.IPv4(data[ethHeaderLen:])
			srcAddr := ip.SourceAddress()
			src := net.IP(srcAddr.AsSlice())
			if !d.cfg.Network.Contains(src) {
				continue
			}
			if !src.Equal(d.cfg.LocalIP) {
				d.learn(src, net.HardwareAddr(eth.SourceAddress()))
			}
			return data
		case header.ARPProtocolNumber:
			d.handleARP(data)
			continue
		default:
			continue
		}
	}
}

// Write sends a frame out via pcap.
func (d *Device) Write(p []byte) (int, error) {
	if err := d.handle.WritePacketData(p); err != nil {
		slog.Error("pcap: write packet", "err", err)
		return 0, nil
	}
	return len(p), nil
}

func (d *Device) handleARP(frame []byte) {
	srcIP, srcMAC, tgtIP := ParseARPRequest(frame)
	if srcIP == nil {
		return
	}
	if srcIP.Equal(d.cfg.LocalIP) {
		return
	}
	if !tgtIP.Equal(d.cfg.LocalIP.To4()) {
		return
	}
	// ARP from outside our CIDR: log only (DEBUG), don't learn or answer.
	if !d.cfg.Network.Contains(srcIP) {
		slog.Debug("arp: request (out of CIDR, ignored)",
			"from_ip", srcIP.String(), "from_mac", srcMAC.String(), "for", tgtIP.String())
		return
	}
	d.learn(srcIP, srcMAC)
	slog.Info("arp: request", "from_ip", srcIP.String(), "from_mac", srcMAC.String(), "for", tgtIP.String())
	reply, err := BuildARPReply(frame, d.cfg.LocalIP, d.cfg.LocalMAC)
	if err != nil || reply == nil {
		return
	}
	if err := d.handle.WritePacketData(reply); err != nil {
		slog.Warn("pcap: arp reply write", "err", err)
		return
	}
	slog.Info("arp: reply", "to_ip", srcIP.String(), "to_mac", srcMAC.String(), "as_ip", d.cfg.LocalIP.String(), "as_mac", d.cfg.LocalMAC.String())
}

func (d *Device) learn(ip net.IP, mac net.HardwareAddr) {
	v4 := ip.To4()
	if v4 == nil || len(mac) != 6 {
		return
	}
	key := string(v4)
	d.mu.Lock()
	prev, ok := d.ipMACTab[key]
	if ok && bytes.Equal(prev, mac) {
		d.mu.Unlock()
		return
	}
	d.ipMACTab[key] = append(net.HardwareAddr(nil), mac...)
	d.mu.Unlock()

	if !ok {
		slog.Info("device joined", "ip", v4.String(), "mac", mac.String())
	}
	if d.cfg.StackGetter != nil {
		if s := d.cfg.StackGetter(); s != nil {
			s.AddStaticNeighbor(
				d.cfg.NICID,
				header.IPv4ProtocolNumber,
				tcpip.AddrFrom4Slice(v4),
				tcpip.LinkAddress(mac),
			)
		}
	}
}

// findPcapDevice locates the pcap interface whose addresses overlap ifce.
func findPcapDevice(ifce net.Interface) (pcap.Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, fmt.Errorf("pcap: find all devs: %w", err)
	}
	addrs, err := ifce.Addrs()
	if err != nil {
		return pcap.Interface{}, fmt.Errorf("pcap: iface addrs: %w", err)
	}
	for _, dev := range devs {
		for _, dAddr := range dev.Addresses {
			for _, ifAddr := range addrs {
				ipnet, ok := ifAddr.(*net.IPNet)
				if !ok {
					continue
				}
				if dAddr.IP.Equal(ipnet.IP) {
					return dev, nil
				}
			}
		}
	}
	// Fall back to matching by name (Windows uses pcap names like \Device\NPF_{...}
	// that won't equal the friendly net.Interface name, but Linux/macOS do match).
	for _, dev := range devs {
		if dev.Name == ifce.Name {
			return dev, nil
		}
	}
	return pcap.Interface{}, fmt.Errorf("pcap: no device found for interface %s", ifce.Name)
}
