// SOCKS5 UDP ASSOCIATE client, hand-rolled because golang.org/x/net/proxy's
// SOCKS5 dialer only implements the CONNECT command (TCP streams). Needed
// now that the container's SOCKS proxy (dante) supports UDP ASSOCIATE, so
// internal DNS queries can use plain DNS-over-UDP instead of being forced
// over DNS-over-TCP.
package dnsrouter

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// socksUDPConn implements net.Conn over a SOCKS5 UDP ASSOCIATE session: each
// Write sends one UDP datagram to target (wrapped in the SOCKS5 UDP header),
// each Read returns one datagram from it (header stripped). The TCP control
// connection must stay open for the association's lifetime and is closed
// together with the UDP socket.
type socksUDPConn struct {
	ctrl   net.Conn
	pc     *net.UDPConn
	relay  *net.UDPAddr
	target *net.UDPAddr
}

// socksUDPAssociate performs the SOCKS5 UDP ASSOCIATE handshake against a
// no-auth SOCKS5 server at socksAddr and returns a net.Conn that transparently
// relays datagrams to/from target through it.
func socksUDPAssociate(socksAddr string, target *net.UDPAddr, timeout time.Duration) (net.Conn, error) {
	ctrl, err := net.DialTimeout("tcp", socksAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial socks control conn: %w", err)
	}
	ctrl.SetDeadline(time.Now().Add(timeout))

	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("send greeting: %w", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, greeting); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("read greeting reply: %w", err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		ctrl.Close()
		return nil, fmt.Errorf("socks5 greeting rejected: %x", greeting)
	}

	// UDP ASSOCIATE request; client address 0.0.0.0:0 lets the server pick.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := ctrl.Write(req); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("send udp associate request: %w", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, resp); err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("read udp associate reply: %w", err)
	}
	if resp[1] != 0x00 {
		ctrl.Close()
		return nil, fmt.Errorf("udp associate rejected, code=%d", resp[1])
	}

	relayIP := net.IP(append([]byte(nil), resp[4:8]...))
	relayPort := binary.BigEndian.Uint16(resp[8:10])
	if relayIP.IsUnspecified() {
		// Some SOCKS servers reply with 0.0.0.0 and expect the client to
		// keep using the address it already connected to.
		host, _, _ := net.SplitHostPort(socksAddr)
		relayIP = net.ParseIP(host)
	}

	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("open local udp socket: %w", err)
	}

	ctrl.SetDeadline(time.Time{})

	return &socksUDPConn{
		ctrl:   ctrl,
		pc:     pc,
		relay:  &net.UDPAddr{IP: relayIP, Port: int(relayPort)},
		target: target,
	}, nil
}

func (c *socksUDPConn) Write(p []byte) (int, error) {
	ip4 := c.target.IP.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("only IPv4 targets are supported, got %s", c.target.IP)
	}

	header := make([]byte, 4+4+2)
	header[3] = 0x01 // ATYP: IPv4
	copy(header[4:8], ip4)
	binary.BigEndian.PutUint16(header[8:10], uint16(c.target.Port))

	packet := append(header, p...)
	if _, err := c.pc.WriteToUDP(packet, c.relay); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socksUDPConn) Read(p []byte) (int, error) {
	buf := make([]byte, 65535)
	n, err := c.pc.Read(buf)
	if err != nil {
		return 0, err
	}

	payload, err := stripSocksUDPHeader(buf[:n])
	if err != nil {
		return 0, err
	}
	return copy(p, payload), nil
}

func stripSocksUDPHeader(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("udp packet too short for socks5 header")
	}

	var headerLen int
	switch data[3] {
	case 0x01: // IPv4
		headerLen = 4 + 4 + 2
	case 0x04: // IPv6
		headerLen = 4 + 16 + 2
	case 0x03: // domain name
		if len(data) < 5 {
			return nil, fmt.Errorf("udp packet too short for domain header")
		}
		headerLen = 5 + int(data[4]) + 2
	default:
		return nil, fmt.Errorf("unknown socks5 udp ATYP: %d", data[3])
	}

	if len(data) < headerLen {
		return nil, fmt.Errorf("udp packet truncated before end of socks5 header")
	}
	return data[headerLen:], nil
}

// ReadFrom and WriteTo make socksUDPConn satisfy net.PacketConn in addition
// to net.Conn. miekg/dns type-asserts on net.PacketConn to decide whether to
// treat a connection as UDP (raw datagrams) or TCP (length-prefixed stream);
// without these, it silently prepends a 2-byte length header meant for TCP,
// corrupting the DNS query for anyone on the other end of the UDP relay.
func (c *socksUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	return n, c.target, err
}

func (c *socksUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *socksUDPConn) Close() error {
	c.pc.Close()
	return c.ctrl.Close()
}

func (c *socksUDPConn) LocalAddr() net.Addr  { return c.pc.LocalAddr() }
func (c *socksUDPConn) RemoteAddr() net.Addr { return c.target }

func (c *socksUDPConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *socksUDPConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *socksUDPConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
