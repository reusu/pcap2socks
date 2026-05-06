package stack

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"pcap2socks/internal/socks5"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// Cap on outstanding TCP handshakes the forwarder will track.
	maxInflightTCP = 1 << 11

	// SOCKS5 dial deadline.
	tcpDialTimeout = 10 * time.Second

	tcpKeepaliveIdle     = 60 * time.Second
	tcpKeepaliveInterval = 30 * time.Second
	tcpKeepaliveCount    = 9
)

func newTCPForwarder(s *stack.Stack, socksServer, gatewayIP string) *tcp.Forwarder {
	return tcp.NewForwarder(s, 0, maxInflightTCP, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst := tcpAddrString(id.LocalAddress, id.LocalPort)
		src := tcpAddrString(id.RemoteAddress, id.RemotePort)
		chain := fmt.Sprintf("%s > %s > socks5://%s > tcp://%s", src, gatewayIP, socksServer, dst)

		// CreateEndpoint must run synchronously inside the forwarder handler:
		// it completes the half-open state. If we delayed this until after the
		// SOCKS5 dial (which can take seconds), the client RST/timeout would
		// have already invalidated the half-open and gvisor would return
		// ConnectionRefused here.
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			slog.Warn(chain+" create endpoint error", "err", terr)
			r.Complete(true)
			return
		}
		r.Complete(false)
		applyTCPSocketOptions(s, ep)
		local := gonet.NewTCPConn(&wq, ep)

		// Dial upstream and bridge in a goroutine so we don't block the
		// forwarder handler while SOCKS5 negotiation happens.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout)
			upstream, err := socks5.Connect(ctx, socksServer, dst)
			cancel()
			if err != nil {
				slog.Warn(chain+" dial error", "err", err)
				local.Close()
				return
			}
			slog.Debug(chain + " create")
			pipe(local, upstream, chain)
		}()
	})
}

// pipe shuttles bytes both ways between local (gvisor) and upstream (SOCKS5)
// until either side closes. Half-close is propagated where supported.
func pipe(local, upstream net.Conn, chain string) {
	defer local.Close()
	defer upstream.Close()

	var up, down int64
	done := make(chan struct{}, 2)
	go func() {
		n, err := io.Copy(upstream, local)
		up = n
		if err != nil && err != io.EOF {
			slog.Debug(chain+" s->t error", "err", err)
		}
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		n, err := io.Copy(local, upstream)
		down = n
		if err != nil && err != io.EOF {
			slog.Debug(chain+" t->s error", "err", err)
		}
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
	slog.Debug(fmt.Sprintf("%s finish (send %d bytes, recv %d bytes)", chain, up, down))
}

func applyTCPSocketOptions(s *stack.Stack, ep tcpip.Endpoint) {
	ep.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(tcpKeepaliveIdle)
	_ = ep.SetSockOpt(&idle)
	interval := tcpip.KeepaliveIntervalOption(tcpKeepaliveInterval)
	_ = ep.SetSockOpt(&interval)
	_ = ep.SetSockOptInt(tcpip.KeepaliveCountOption, tcpKeepaliveCount)

	var sndBuf tcpip.TCPSendBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &sndBuf); err == nil {
		ep.SocketOptions().SetSendBufferSize(int64(sndBuf.Default), false)
	}
	var rcvBuf tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &rcvBuf); err == nil {
		ep.SocketOptions().SetReceiveBufferSize(int64(rcvBuf.Default), false)
	}
}

func tcpAddrString(addr tcpip.Address, port uint16) string {
	ip := net.IP(addr.AsSlice())
	return fmt.Sprintf("%s:%d", ip.String(), port)
}
