# pcap2socks

**pcap2socks** is a proxy that redirects LAN traffic to a SOCKS5 proxy with pcap, written in Go.

A Go reimplementation built on top of [gVisor](https://gvisor.dev/)'s userspace TCP/IP stack. Inspired by [zhxie/pcap2socks](https://github.com/zhxie/pcap2socks).

_pcap2socks is designed to accelerate games on game consoles and other devices that can only forward traffic through a LAN gateway._

## Features

- **Redirect Traffic**: Redirect TCP and UDP traffic from devices on the LAN to a SOCKS5 proxy.
- **Userspace Stack**: Built on gVisor — no TUN/TAP, no kernel routing changes, no IP-forwarding flag flips.
- **Proxy ARP**: Replies to ARP requests for the gateway IP inline; learns IP→MAC pairs from observed traffic and teaches gVisor's neighbor cache so replies route correctly.
- **DNS Bypass**: Optionally relay UDP/53 directly to a DNS resolver instead of going through SOCKS5 — much faster for the short-lived single-packet exchanges DNS produces.
- **Cross Platform**: macOS, Linux, and Windows (via Npcap).

## Dependencies

1. [Npcap](https://nmap.org/npcap/) on Windows (install with the "WinPcap API-compatible Mode" option), [libpcap](https://www.tcpdump.org/) on macOS, Linux, and others.
2. Go 1.25+ (CGO required).

## Build

```
./build.sh
```

The binary is written to `build/pcap2socks_<os>_<arch>`. Cross-compilation works with the matching C toolchain:

```
GOOS=linux   GOARCH=amd64 CC=x86_64-linux-gnu-gcc   ./build.sh
GOOS=linux   GOARCH=arm64 CC=aarch64-linux-gnu-gcc  ./build.sh
GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc ./build.sh
```

## Usage

```
pcap2socks -s <SRC> -d <SOCKS5> [-i <IFACE>] [--mtu <N>] [--dns <DNS>] [-v]
```

Configure the source device (the console / phone / VM you want to proxy) to use the IP printed at startup as its **gateway**. pcap2socks intercepts that traffic via libpcap and tunnels it through the upstream SOCKS5 server.

### Flags

`-h`: Print help information.

`-v`: Verbose (DEBUG-level) logging. Also widens the ARP capture filter so out-of-CIDR ARP requests are logged (but still ignored).

### Options

`-s <ADDRESS>`: **Source**. Either a single IPv4 (e.g. `192.168.1.10`, treated as the gateway IP within an inferred `/24`) or a CIDR (e.g. `192.168.1.0/24`, gateway becomes the first usable host inside the network).

`-d <ADDRESS>`: **Upstream SOCKS5 server**, as `host:port`. Required.

`-i <INTERFACE>`: **Capture interface**. If omitted, pcap2socks auto-detects a usable interface — pass this if auto-detection picks the wrong one or there are multiple candidates.

`--mtu <VALUE>`: **MTU override**. By default the host interface MTU is used; the source device should be configured with this MTU minus 14 bytes of Ethernet overhead (the value printed at startup).

`--dns <ADDRESS>`: **DNS relay**. When set, UDP/53 traffic is sent directly to this resolver (`host:port`, or just `host` for port 53) instead of going through SOCKS5. Recommended when your SOCKS5 server's UDP ASSOCIATE is slow or unreliable for DNS.

## Examples

Acting as the gateway for a `/24` LAN, forwarding through a local SOCKS5 server:

```
sudo pcap2socks -s 192.168.50.0/24 -d 127.0.0.1:1080
```

With direct DNS relay (UDP/53 bypasses SOCKS5):

```
sudo pcap2socks -s 192.168.50.0/24 -d 127.0.0.1:1080 --dns 8.8.8.8
```

When pcap2socks starts, it prints the LAN settings to apply on the source device:

```
Configure the source device with these settings:
----------------------------------------------------------
  IP Address:  192.168.50.2 - 192.168.50.254
  Subnet Mask: 255.255.255.0
  Gateway:     192.168.50.1
  MTU:         1486 (or lower)
----------------------------------------------------------
```

## Troubleshoot

1. Packets sent by the source device must only be handled by pcap2socks, so disable IP forwarding on the host:

   ```
   # Linux
   sysctl -w net.ipv4.ip_forward=0

   # macOS
   sysctl -w net.inet.ip.forwarding=0
   ```

2. pcap2socks needs raw-socket access. On Linux you can avoid running as root by granting the binary the capability:

   ```
   setcap cap_net_raw+ep /path/to/pcap2socks
   ```

## Limitations

1. **IPv4 only**. IPv6 is not supported.
2. **SOCKS5 NO_AUTH only**. Username/password (`0x02`) and GSS-API (`0x01`) are not implemented.
3. **No traffic shaping**. A single heavy connection can saturate the relay; other connections may be starved.

## Known Issues

1. Software that implements its own IP forwarding on the host (e.g. VMware Workstation on Windows) may grab packets that should belong to pcap2socks, causing erratic behavior.
