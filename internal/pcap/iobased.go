package pcap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// outQueueLen is the number of outbound packets buffered in the channel
// endpoint before the stack starts dropping. Matches the reference impl.
const outQueueLen = 1 << 10

// ReadWriter is the contract the iobased endpoint expects from a packet
// source/sink (in our case, the pcap device).
//
// Done returns a channel that is closed when the source is shutting down so
// the dispatch loop can exit promptly instead of spinning on Read returning
// nil.
type ReadWriter interface {
	Read() []byte
	Write(p []byte) (int, error)
	Done() <-chan struct{}
}

// Endpoint adapts a frame-oriented ReadWriter (libpcap) into a gvisor
// stack.LinkEndpoint by wrapping a channel.Endpoint and pumping frames
// in/out on attach.
type Endpoint struct {
	*channel.Endpoint
	rw   ReadWriter
	once sync.Once
	wg   sync.WaitGroup
}

// NewEndpoint constructs an iobased endpoint over rw. mtu must be > 0.
// mac is the gateway MAC (bound onto the underlying channel endpoint).
func NewEndpoint(rw ReadWriter, mtu uint32, mac net.HardwareAddr) (*Endpoint, error) {
	if mtu == 0 {
		return nil, errors.New("iobased: mtu is zero")
	}
	if rw == nil {
		return nil, errors.New("iobased: rw is nil")
	}
	linkAddr, err := tcpip.ParseMACAddress(mac.String())
	if err != nil {
		return nil, fmt.Errorf("iobased: parse mac: %w", err)
	}
	return &Endpoint{
		Endpoint: channel.New(outQueueLen, mtu, linkAddr),
		rw:       rw,
	}, nil
}

// Attach starts the read/write pump goroutines on first call. Re-attaches
// after detach are not supported (matches stack semantics).
func (e *Endpoint) Attach(d stack.NetworkDispatcher) {
	e.Endpoint.Attach(d)
	e.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		e.wg.Add(2)
		go func() {
			defer e.wg.Done()
			e.outboundLoop(ctx)
		}()
		go func() {
			defer e.wg.Done()
			e.dispatchLoop(cancel)
		}()
	})
}

// Wait blocks until the read/write pumps have exited.
func (e *Endpoint) Wait() { e.wg.Wait() }

func (e *Endpoint) dispatchLoop(cancel context.CancelFunc) {
	defer cancel()
	done := e.rw.Done()
	for {
		select {
		case <-done:
			return
		default:
		}
		data := e.rw.Read()
		if len(data) == 0 {
			// Distinguish "Read returned because device closed" from "Read
			// got an uninteresting frame and returned empty"; we never block
			// here, just give the next loop iteration a chance to observe done.
			select {
			case <-done:
				return
			default:
				continue
			}
		}
		if !e.IsAttached() {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data),
		})
		e.InjectInbound(header.EthernetProtocolAll, pkt)
		pkt.DecRef()
	}
}

func (e *Endpoint) outboundLoop(ctx context.Context) {
	for {
		pkt := e.ReadContext(ctx)
		if pkt == nil {
			return
		}
		e.writePacket(pkt)
	}
}

func (e *Endpoint) writePacket(pkt *stack.PacketBuffer) {
	defer pkt.DecRef()
	view := pkt.ToView()
	defer view.Release()
	if _, err := view.WriteTo(writerFunc(e.rw.Write)); err != nil {
		// Underlying device write errors are non-fatal here; the device
		// logs them. Dropping the packet is the right behavior.
		_ = err
	}
}

// writerFunc lets us pass a Write method to view.WriteTo.
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
