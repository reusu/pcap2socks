// Package socks5 implements a minimal SOCKS5 client (RFC 1928) supporting
// only the NO AUTHENTICATION method. It exposes TCP CONNECT and UDP ASSOCIATE.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	version5 = 0x05
	noAuth   = 0x00

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded = 0x00
)

// Connect performs a SOCKS5 CONNECT to target via server. target is "host:port"
// where host may be an IP literal or domain name. Returns the live TCP conn.
func Connect(ctx context.Context, server, target string) (net.Conn, error) {
	c, err := dial(ctx, server)
	if err != nil {
		return nil, err
	}
	// Apply ctx deadline to the handshake exchange too — without this, a
	// SOCKS server that accepts TCP but never speaks would hang us forever.
	// Cleared on success so io.Copy in the caller isn't artificially deadlined.
	if err := withCtxDeadline(ctx, c, func() error {
		if err := handshake(c); err != nil {
			return err
		}
		addr, err := encodeAddr(target)
		if err != nil {
			return err
		}
		if _, err := writeRequest(c, cmdConnect, addr); err != nil {
			return err
		}
		_, err = readReply(c)
		return err
	}); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// UDPAssociate performs a SOCKS5 UDP ASSOCIATE handshake against server.
// Returns the control TCP connection (must remain open for the lifetime of
// the association — closing it tears down the relay) and the UDP relay
// address the caller should send/receive UDP packets through.
func UDPAssociate(ctx context.Context, server string) (net.Conn, *net.UDPAddr, error) {
	c, err := dial(ctx, server)
	if err != nil {
		return nil, nil, err
	}

	var relay *net.UDPAddr
	if err := withCtxDeadline(ctx, c, func() error {
		if err := handshake(c); err != nil {
			return err
		}
		// Per RFC 1928 §6: if the client doesn't yet know its source addr/port,
		// it MUST send all zeros. We do; the server's reply contains the relay.
		zeroAddr := []byte{atypIPv4, 0, 0, 0, 0, 0, 0}
		if _, err := writeRequest(c, cmdUDPAssociate, zeroAddr); err != nil {
			return err
		}
		bnd, err := readReply(c)
		if err != nil {
			return err
		}
		relay = bnd.UDPAddr()
		if relay == nil {
			return fmt.Errorf("socks5: server returned non-IP relay address")
		}
		// If the server replies with an unspecified IP (0.0.0.0/::), use the
		// server's host — the relay lives on the same machine.
		if relay.IP.IsUnspecified() {
			host, _, _ := net.SplitHostPort(server)
			ip := net.ParseIP(host)
			if ip == nil {
				ips, lerr := net.DefaultResolver.LookupIP(ctx, "ip", host)
				if lerr != nil || len(ips) == 0 {
					return fmt.Errorf("socks5: resolve relay host %s: %w", host, lerr)
				}
				ip = ips[0]
			}
			relay.IP = ip
		}
		return nil
	}); err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, relay, nil
}

// withCtxDeadline applies ctx's deadline to c for the duration of fn, then
// clears it. If ctx has no deadline, fn runs without one.
func withCtxDeadline(ctx context.Context, c net.Conn, fn func() error) error {
	if dl, ok := ctx.Deadline(); ok {
		if err := c.SetDeadline(dl); err != nil {
			return err
		}
		defer c.SetDeadline(time.Time{})
	}
	return fn()
}

// EncodeUDP wraps payload in a SOCKS5 UDP request header (§7) addressed to dst.
func EncodeUDP(dst *net.UDPAddr, payload []byte) []byte {
	addr := udpAddrBytes(dst)
	out := make([]byte, 3+len(addr)+len(payload))
	// RSV (2) + FRAG (1)
	out[0], out[1], out[2] = 0, 0, 0
	copy(out[3:], addr)
	copy(out[3+len(addr):], payload)
	return out
}

// DecodeUDP parses a SOCKS5 UDP datagram, returning the inner source addr and payload.
// The returned payload is a slice into buf (no copy).
func DecodeUDP(buf []byte) (*net.UDPAddr, []byte, error) {
	if len(buf) < 4 {
		return nil, nil, fmt.Errorf("socks5: udp packet too short")
	}
	if buf[2] != 0 {
		return nil, nil, fmt.Errorf("socks5: udp fragmentation not supported")
	}
	addr, n, err := decodeAddr(buf[3:])
	if err != nil {
		return nil, nil, err
	}
	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return nil, nil, fmt.Errorf("socks5: udp packet has non-IP src")
	}
	return udpAddr, buf[3+n:], nil
}

// ---- internals ----

func dial(ctx context.Context, server string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", server)
}

func handshake(c net.Conn) error {
	// Method negotiation: VER NMETHODS METHODS
	if _, err := c.Write([]byte{version5, 1, noAuth}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		return fmt.Errorf("socks5: read method reply: %w", err)
	}
	if resp[0] != version5 {
		return fmt.Errorf("socks5: unexpected version %#x", resp[0])
	}
	if resp[1] != noAuth {
		return fmt.Errorf("socks5: server requires auth method %#x; only NO_AUTH supported", resp[1])
	}
	return nil
}

func writeRequest(c net.Conn, cmd byte, addr []byte) (int, error) {
	req := make([]byte, 0, 3+len(addr))
	req = append(req, version5, cmd, 0x00) // VER CMD RSV
	req = append(req, addr...)
	return c.Write(req)
}

func readReply(c net.Conn) (Addr, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return nil, fmt.Errorf("socks5: read reply head: %w", err)
	}
	if head[0] != version5 {
		return nil, fmt.Errorf("socks5: bad reply version %#x", head[0])
	}
	if head[1] != repSucceeded {
		return nil, fmt.Errorf("socks5: request failed: %s", replyError(head[1]))
	}
	// Read BND.ADDR + BND.PORT.
	switch head[3] {
	case atypIPv4:
		buf := make([]byte, 1+net.IPv4len+2)
		buf[0] = atypIPv4
		if _, err := io.ReadFull(c, buf[1:]); err != nil {
			return nil, err
		}
		return Addr(buf), nil
	case atypIPv6:
		buf := make([]byte, 1+net.IPv6len+2)
		buf[0] = atypIPv6
		if _, err := io.ReadFull(c, buf[1:]); err != nil {
			return nil, err
		}
		return Addr(buf), nil
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return nil, err
		}
		buf := make([]byte, 2+int(l[0])+2)
		buf[0] = atypDomain
		buf[1] = l[0]
		if _, err := io.ReadFull(c, buf[2:]); err != nil {
			return nil, err
		}
		return Addr(buf), nil
	default:
		return nil, fmt.Errorf("socks5: unknown ATYP %#x", head[3])
	}
}

// Addr is a SOCKS5-encoded address (ATYP + addr bytes + 2-byte port).
type Addr []byte

// UDPAddr converts the encoded address to a *net.UDPAddr, or nil if it's a domain.
func (a Addr) UDPAddr() *net.UDPAddr {
	if len(a) == 0 {
		return nil
	}
	switch a[0] {
	case atypIPv4:
		if len(a) != 1+net.IPv4len+2 {
			return nil
		}
		return &net.UDPAddr{
			IP:   net.IP(a[1 : 1+net.IPv4len]),
			Port: int(binary.BigEndian.Uint16(a[1+net.IPv4len:])),
		}
	case atypIPv6:
		if len(a) != 1+net.IPv6len+2 {
			return nil
		}
		return &net.UDPAddr{
			IP:   net.IP(a[1 : 1+net.IPv6len]),
			Port: int(binary.BigEndian.Uint16(a[1+net.IPv6len:])),
		}
	}
	return nil
}

func encodeAddr(target string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("socks5: parse %q: %w", target, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("socks5: parse port %q: %w", portStr, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out := make([]byte, 1+net.IPv4len+2)
			out[0] = atypIPv4
			copy(out[1:], v4)
			binary.BigEndian.PutUint16(out[1+net.IPv4len:], uint16(port))
			return out, nil
		}
		out := make([]byte, 1+net.IPv6len+2)
		out[0] = atypIPv6
		copy(out[1:], ip.To16())
		binary.BigEndian.PutUint16(out[1+net.IPv6len:], uint16(port))
		return out, nil
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("socks5: domain name %q too long", host)
	}
	out := make([]byte, 2+len(host)+2)
	out[0] = atypDomain
	out[1] = byte(len(host))
	copy(out[2:], host)
	binary.BigEndian.PutUint16(out[2+len(host):], uint16(port))
	return out, nil
}

func udpAddrBytes(a *net.UDPAddr) []byte {
	if v4 := a.IP.To4(); v4 != nil {
		out := make([]byte, 1+net.IPv4len+2)
		out[0] = atypIPv4
		copy(out[1:], v4)
		binary.BigEndian.PutUint16(out[1+net.IPv4len:], uint16(a.Port))
		return out
	}
	out := make([]byte, 1+net.IPv6len+2)
	out[0] = atypIPv6
	copy(out[1:], a.IP.To16())
	binary.BigEndian.PutUint16(out[1+net.IPv6len:], uint16(a.Port))
	return out
}

func decodeAddr(b []byte) (Addr, int, error) {
	if len(b) < 1 {
		return nil, 0, errors.New("socks5: empty addr")
	}
	switch b[0] {
	case atypIPv4:
		if len(b) < 1+net.IPv4len+2 {
			return nil, 0, errors.New("socks5: short ipv4 addr")
		}
		n := 1 + net.IPv4len + 2
		out := make(Addr, n)
		copy(out, b[:n])
		return out, n, nil
	case atypIPv6:
		if len(b) < 1+net.IPv6len+2 {
			return nil, 0, errors.New("socks5: short ipv6 addr")
		}
		n := 1 + net.IPv6len + 2
		out := make(Addr, n)
		copy(out, b[:n])
		return out, n, nil
	case atypDomain:
		if len(b) < 2 {
			return nil, 0, errors.New("socks5: short domain addr")
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return nil, 0, errors.New("socks5: short domain addr body")
		}
		n := 2 + l + 2
		out := make(Addr, n)
		copy(out, b[:n])
		return out, n, nil
	}
	return nil, 0, fmt.Errorf("socks5: unknown ATYP %#x", b[0])
}

func replyError(rep byte) string {
	switch rep {
	case 1:
		return "general SOCKS server failure"
	case 2:
		return "connection not allowed by ruleset"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "TTL expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	}
	return fmt.Sprintf("unknown reply code %d", rep)
}
