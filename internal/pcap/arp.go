package pcap

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	ethTypeIPv4 uint16 = 0x0800
	ethTypeARP  uint16 = 0x0806

	arpHWEthernet uint16 = 0x0001
	arpProtoIPv4  uint16 = 0x0800

	arpOpRequest uint16 = 1
	arpOpReply   uint16 = 2

	ethHeaderLen = 14
	arpFrameLen  = 42 // 14 ethernet + 28 ARP IPv4
)

var ethBroadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// BuildGratuitousARP returns an ethernet+ARP frame announcing localIP→localMAC,
// broadcast to the LAN. Used at startup so devices update their ARP caches
// when pcap2socks first comes up.
func BuildGratuitousARP(localIP net.IP, localMAC net.HardwareAddr) ([]byte, error) {
	v4 := localIP.To4()
	if v4 == nil {
		return nil, errors.New("arp: localIP must be IPv4")
	}
	if len(localMAC) != 6 {
		return nil, errors.New("arp: localMAC must be 6 bytes")
	}
	return buildARP(localMAC, ethBroadcast, arpOpRequest, localMAC, v4, net.HardwareAddr{0, 0, 0, 0, 0, 0}, v4), nil
}

// BuildARPReply parses an inbound ARP request frame and constructs a reply
// from (localIP, localMAC). Returns (nil, nil) if the frame isn't an ARP
// request we should answer.
func BuildARPReply(req []byte, localIP net.IP, localMAC net.HardwareAddr) ([]byte, error) {
	if len(req) < arpFrameLen {
		return nil, nil
	}
	if binary.BigEndian.Uint16(req[12:14]) != ethTypeARP {
		return nil, nil
	}
	a := req[ethHeaderLen:]
	if binary.BigEndian.Uint16(a[0:2]) != arpHWEthernet ||
		binary.BigEndian.Uint16(a[2:4]) != arpProtoIPv4 ||
		a[4] != 6 || a[5] != 4 {
		return nil, nil
	}
	if binary.BigEndian.Uint16(a[6:8]) != arpOpRequest {
		return nil, nil
	}
	srcMAC := net.HardwareAddr(a[8:14])
	srcIP := net.IP(a[14:18])
	tgtIP := net.IP(a[24:28])
	v4 := localIP.To4()
	if v4 == nil || !tgtIP.Equal(v4) {
		return nil, nil
	}
	return buildARP(localMAC, srcMAC, arpOpReply, localMAC, v4, srcMAC, srcIP), nil
}

// ParseARPRequest extracts (srcIP, srcMAC, tgtIP) from an ethernet+ARP frame
// if it is a request. Returns (nil, nil, nil) if not parseable as such.
func ParseARPRequest(frame []byte) (srcIP net.IP, srcMAC net.HardwareAddr, tgtIP net.IP) {
	if len(frame) < arpFrameLen {
		return nil, nil, nil
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeARP {
		return nil, nil, nil
	}
	a := frame[ethHeaderLen:]
	if binary.BigEndian.Uint16(a[6:8]) != arpOpRequest {
		return nil, nil, nil
	}
	return net.IP(a[14:18]), net.HardwareAddr(a[8:14]), net.IP(a[24:28])
}

func buildARP(ethSrc, ethDst net.HardwareAddr, op uint16, sha net.HardwareAddr, spa net.IP, tha net.HardwareAddr, tpa net.IP) []byte {
	out := make([]byte, arpFrameLen)
	// Ethernet header
	copy(out[0:6], ethDst)
	copy(out[6:12], ethSrc)
	binary.BigEndian.PutUint16(out[12:14], ethTypeARP)
	// ARP body
	a := out[ethHeaderLen:]
	binary.BigEndian.PutUint16(a[0:2], arpHWEthernet)
	binary.BigEndian.PutUint16(a[2:4], arpProtoIPv4)
	a[4] = 6 // hw addr len
	a[5] = 4 // proto addr len
	binary.BigEndian.PutUint16(a[6:8], op)
	copy(a[8:14], sha)
	copy(a[14:18], spa.To4())
	copy(a[18:24], tha)
	copy(a[24:28], tpa.To4())
	return out
}
