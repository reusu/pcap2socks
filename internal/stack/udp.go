package stack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"pcap2socks/internal/socks5"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	udpDialTimeout  = 5 * time.Second
	udpIdleTimeout  = 60 * time.Second
	udpMaxPacketLen = 65535

	// dnsIdleTimeout is much shorter than udpIdleTimeout because DNS is
	// ask-once-answer-once; keeping the relay socket open longer just wastes
	// fds when the device burns through one ephemeral src port per query.
	dnsIdleTimeout = 3 * time.Second

	// dnsMaxPacketLen covers EDNS0 responses (typically negotiated to 1232,
	// 4096, or up to 65535). 4096 handles the common ceiling without burning
	// 64K per flow like udpMaxPacketLen would.
	dnsMaxPacketLen = 4096
)

func newUDPForwarder(s *stack.Stack, socksServer, gatewayIP, dnsRelay string) *udp.Forwarder {
	return udp.NewForwarder(s, func(r *udp.ForwarderRequest) (handled bool) {
		id := r.ID()
		dst := &net.UDPAddr{IP: net.IP(id.LocalAddress.AsSlice()), Port: int(id.LocalPort)}
		src := &net.UDPAddr{IP: net.IP(id.RemoteAddress.AsSlice()), Port: int(id.RemotePort)}

		// CreateEndpoint must be synchronous inside the forwarder handler.
		// If we delay it (e.g. inside a goroutine), additional inbound packets
		// for the same 5-tuple will see no registered endpoint and fire the
		// forwarder again, racing two concurrent CreateEndpoint calls — the
		// loser returns "port is in use".
		dnsBypass := dnsRelay != "" && id.LocalPort == 53
		chain := udpChain(src, dst, gatewayIP, socksServer, dnsRelay, dnsBypass)

		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			slog.Warn(chain+" create endpoint error", "err", terr)
			return true
		}
		local := gonet.NewUDPConn(&wq, ep)

		if dnsBypass {
			go relayDNS(dnsRelay, chain, src, local)
		} else {
			go relayUDP(socksServer, chain, src, dst, local)
		}
		return true
	})
}

func udpChain(src, dst *net.UDPAddr, gw, socks, dns string, dnsBypass bool) string {
	if dnsBypass {
		return fmt.Sprintf("%s > %s > dns@%s > udp://%s", src, gw, dns, dst)
	}
	return fmt.Sprintf("%s > %s > socks5://%s > udp://%s", src, gw, socks, dst)
}

func relayDNS(dnsRelay, chain string, src *net.UDPAddr, local *gonet.UDPConn) {
	defer local.Close()

	relayAddr, err := net.ResolveUDPAddr("udp", dnsRelay)
	if err != nil {
		slog.Warn(chain+" resolve relay error", "err", err)
		return
	}
	rc, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		slog.Warn(chain+" relay dial error", "err", err)
		return
	}
	defer rc.Close()

	var sent, recv int64
	slog.Debug(chain + " create")
	defer func() {
		slog.Debug(fmt.Sprintf("%s finish (send %d bytes, recv %d bytes)",
			chain, atomic.LoadInt64(&sent), atomic.LoadInt64(&recv)))
	}()

	// local -> relay
	go func() {
		buf := make([]byte, dnsMaxPacketLen)
		for {
			_ = local.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
			n, _, rerr := local.ReadFrom(buf)
			if rerr != nil {
				_ = rc.Close()
				return
			}
			if _, werr := rc.Write(buf[:n]); werr != nil {
				slog.Debug(chain+" s->t error", "err", werr)
				_ = local.Close()
				return
			}
			atomic.AddInt64(&sent, int64(n))
		}
	}()

	// relay -> local
	buf := make([]byte, dnsMaxPacketLen)
	for {
		_ = rc.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
		n, _, rerr := rc.ReadFromUDP(buf)
		if rerr != nil {
			return
		}
		if _, werr := local.WriteTo(buf[:n], src); werr != nil {
			slog.Debug(chain+" t->s error", "err", werr)
			return
		}
		atomic.AddInt64(&recv, int64(n))
	}
}

func relayUDP(socksServer, chain string, src, dst *net.UDPAddr, local *gonet.UDPConn) {
	defer local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), udpDialTimeout)
	tcpCtl, relay, err := socks5.UDPAssociate(ctx, socksServer)
	cancel()
	if err != nil {
		slog.Warn(chain+" associate error", "err", err)
		return
	}
	defer tcpCtl.Close()

	relayConn, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		slog.Warn(chain+" relay dial error", "err", err)
		return
	}
	defer relayConn.Close()

	var sent, recv int64
	slog.Debug(chain + " create")
	defer func() {
		slog.Debug(fmt.Sprintf("%s finish (send %d bytes, recv %d bytes)",
			chain, atomic.LoadInt64(&sent), atomic.LoadInt64(&recv)))
	}()

	// done signals all helper goroutines (tcpCtl reader, idle watchdog) to
	// exit when relayUDP returns. Without this, the watchdog kept running
	// for up to udpIdleTimeout (60s) after every flow ended, leaking
	// goroutines proportional to flow churn.
	done := make(chan struct{})
	defer close(done)

	// If the SOCKS5 control TCP closes, tear the whole flow down (RFC 1928).
	go func() {
		buf := make([]byte, 64)
		for {
			if _, rerr := tcpCtl.Read(buf); rerr != nil {
				_ = local.Close()
				_ = relayConn.Close()
				return
			}
		}
	}()

	idleReset := make(chan struct{}, 16)
	// Idle watchdog: if no traffic in either direction for udpIdleTimeout, kill the flow.
	go func() {
		t := time.NewTimer(udpIdleTimeout)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-idleReset:
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
				t.Reset(udpIdleTimeout)
			case <-t.C:
				_ = local.Close()
				_ = relayConn.Close()
				_ = tcpCtl.Close()
				return
			}
		}
	}()

	// local -> SOCKS5 relay
	go func() {
		buf := make([]byte, udpMaxPacketLen)
		for {
			n, _, rerr := local.ReadFrom(buf)
			if rerr != nil {
				if !errors.Is(rerr, net.ErrClosed) {
					slog.Debug(chain+" s->t error", "err", rerr)
				}
				_ = relayConn.Close()
				return
			}
			pkt := socks5.EncodeUDP(dst, buf[:n])
			if _, werr := relayConn.Write(pkt); werr != nil {
				slog.Debug(chain+" s->t error", "err", werr)
				_ = local.Close()
				return
			}
			atomic.AddInt64(&sent, int64(n))
			select {
			case idleReset <- struct{}{}:
			default:
			}
		}
	}()

	// SOCKS5 relay -> local
	buf := make([]byte, udpMaxPacketLen)
	for {
		n, _, rerr := relayConn.ReadFromUDP(buf)
		if rerr != nil {
			if !errors.Is(rerr, net.ErrClosed) {
				slog.Debug(chain+" t->s error", "err", rerr)
			}
			return
		}
		_, payload, derr := socks5.DecodeUDP(buf[:n])
		if derr != nil {
			slog.Debug(chain+" decode error", "err", derr)
			continue
		}
		if _, werr := local.WriteTo(payload, src); werr != nil {
			slog.Debug(chain+" t->s error", "err", werr)
			return
		}
		atomic.AddInt64(&recv, int64(len(payload)))
		select {
		case idleReset <- struct{}{}:
		default:
		}
	}
}
