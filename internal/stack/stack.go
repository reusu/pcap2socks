// Package stack wires up a gvisor userspace IPv4 stack with TCP and UDP
// forwarders that tunnel application flows through an upstream SOCKS5 proxy.
package stack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Config configures the userspace stack.
type Config struct {
	LinkEndpoint stack.LinkEndpoint
	NICID        tcpip.NICID
	// SocksServer is the upstream SOCKS5 server "host:port".
	SocksServer string
	// GatewayIP is the IP we present as the LAN gateway (for log chains).
	GatewayIP string
	// DNSRelay, when non-empty, diverts all UDP/53 traffic directly to this
	// host:port instead of going through SOCKS5 (which is wasteful for the
	// short-lived single-packet exchanges that DNS produces).
	DNSRelay string
}

// Create builds a *stack.Stack and binds the link endpoint to it. Forwarders
// are installed BEFORE NIC creation, otherwise inbound packets can race the
// stack and fall on the floor.
func Create(cfg Config) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
	})

	// Install forwarders first so the NIC can deliver immediately on creation.
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, newTCPForwarder(s, cfg.SocksServer, cfg.GatewayIP).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, newUDPForwarder(s, cfg.SocksServer, cfg.GatewayIP, cfg.DNSRelay).HandlePacket)

	if err := s.CreateNIC(cfg.NICID, cfg.LinkEndpoint); err != nil {
		return nil, fmt.Errorf("stack: create nic: %s", err)
	}

	// Promiscuous + spoofing so we accept packets to any address (the
	// devices on the LAN are sending to internet IPs we don't actually own)
	// and so we can send replies from those same addresses.
	if err := s.SetPromiscuousMode(cfg.NICID, true); err != nil {
		return nil, fmt.Errorf("stack: promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(cfg.NICID, true); err != nil {
		return nil, fmt.Errorf("stack: spoofing: %s", err)
	}

	// Default route: 0.0.0.0/0 via this NIC. We don't set a NextHop; with
	// promiscuous + spoofing the stack will respond as the destination.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         cfg.NICID,
		},
	})

	return s, nil
}
