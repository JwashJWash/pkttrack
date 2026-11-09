package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ProbeReq describes test traffic the user wants to send to a target.
type ProbeReq struct {
	IP      net.IP
	Host    string // hostname for TLS SNI / HTTP Host / DNS query, if the target has one
	Port    uint16
	Proto   Proto // TCP, UDP or ICMP (never Any once resolved)
	Count   int
	Payload string // optional custom bytes to send (TCP/UDP)
	Timeout time.Duration
}

func (r ProbeReq) Addr() string {
	if r.Proto == ProtoICMP {
		return r.IP.String()
	}
	return net.JoinHostPort(r.IP.String(), strconv.Itoa(int(r.Port)))
}

func (r ProbeReq) String() string {
	return fmt.Sprintf("%s %s", r.Proto.String(), r.Addr())
}

// ProbeResult is the outcome of one probe attempt.
type ProbeResult struct {
	OK        bool
	Summary   string
	LocalAddr string // our ip:port, so the UI can tag our own packets
	RTT       time.Duration
}

var probeID = os.Getpid() & 0xffff

// RunProbe sends one round of test traffic and reports what came back.
func RunProbe(r ProbeReq, seq int) ProbeResult {
	if r.Timeout == 0 {
		r.Timeout = 3 * time.Second
	}
	switch r.Proto {
	case ProtoTCP:
		return probeTCP(r)
	case ProtoUDP:
		return probeUDP(r)
	case ProtoICMP:
		return probeICMP(r, seq)
	}
	return ProbeResult{Summary: "no probe method for " + r.Proto.String()}
}

func describeNetErr(err error, timeout time.Duration) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused — nothing is listening (target answered with RST / ICMP unreachable)"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable — no route to host"
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return "not permitted by the OS / firewall: " + err.Error()
	case errors.As(err, &ne) && ne.Timeout():
		return fmt.Sprintf("no answer within %s (dropped or filtered by a firewall?)", timeout)
	}
	return err.Error()
}

func probeTCP(r ProbeReq) ProbeResult {
	start := time.Now()
	c, err := net.DialTimeout("tcp", r.Addr(), r.Timeout)
	if err != nil {
		return ProbeResult{Summary: "TCP connect " + describeNetErr(err, r.Timeout)}
	}
	defer c.Close()
	rtt := time.Since(start)
	res := ProbeResult{OK: true, RTT: rtt, LocalAddr: c.LocalAddr().String(),
		Summary: fmt.Sprintf("port open — handshake done in %s", fmtDur(rtt))}
	_ = c.SetDeadline(time.Now().Add(r.Timeout))
	buf := make([]byte, 2048)

	switch {
	case r.Payload != "":
		n, err := c.Write([]byte(r.Payload))
		if err != nil {
			res.Summary += " · send failed: " + err.Error()
			return res
		}
		_ = c.SetReadDeadline(time.Now().Add(min(r.Timeout, 1500*time.Millisecond)))
		m, _ := c.Read(buf)
		res.Summary += fmt.Sprintf(" · sent %s, got %s back", humanBytes(n), humanBytes(m))
		if m > 0 {
			res.Summary += ": " + firstLine(buf[:m])
		}
	case isTLSPort(r.Port):
		cfg := &tls.Config{InsecureSkipVerify: true} // we're testing reachability, not trust
		if r.Host != "" && net.ParseIP(r.Host) == nil {
			cfg.ServerName = r.Host
		}
		tc := tls.Client(c, cfg)
		if err := tc.Handshake(); err != nil {
			res.Summary += " · TLS handshake failed: " + err.Error()
			return res
		}
		st := tc.ConnectionState()
		res.Summary += fmt.Sprintf(" · %s handshake ok (%s)", tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
		if len(st.PeerCertificates) > 0 {
			res.Summary += " cert CN=" + st.PeerCertificates[0].Subject.CommonName
		}
		_ = tc.Close()
	case isHTTPPort(r.Port):
		host := r.Host
		if host == "" {
			host = r.IP.String()
		}
		fmt.Fprintf(c, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: pkttrack-probe\r\nConnection: close\r\n\r\n", host)
		if n, _ := c.Read(buf); n > 0 {
			res.Summary += " · " + firstLine(buf[:n])
		} else {
			res.Summary += " · no HTTP response"
		}
	default:
		// Many services (SSH, SMTP, FTP…) greet first: wait briefly for a banner.
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, _ := c.Read(buf); n > 0 {
			res.Summary += " · banner: " + firstLine(buf[:n])
		}
	}
	return res
}

func isTLSPort(p uint16) bool {
	switch p {
	case 443, 8443, 465, 853, 993, 995, 636, 5986, 6443:
		return true
	}
	return false
}

func isHTTPPort(p uint16) bool {
	switch p {
	case 80, 8000, 8008, 8080, 8888, 3000, 5000:
		return true
	}
	return false
}

func probeUDP(r ProbeReq) ProbeResult {
	c, err := net.Dial("udp", r.Addr())
	if err != nil {
		return ProbeResult{Summary: "UDP " + describeNetErr(err, r.Timeout)}
	}
	defer c.Close()
	res := ProbeResult{LocalAddr: c.LocalAddr().String()}

	payload, kind := []byte(r.Payload), "datagram"
	if r.Payload == "" {
		switch r.Port {
		case 53, 5353:
			name := "example.com"
			if r.Host != "" && net.ParseIP(r.Host) == nil {
				name = r.Host
			}
			payload, kind = dnsQuery(name), "DNS query for "+name
		case 123:
			payload = make([]byte, 48)
			payload[0] = 0x1b // NTP v3 client request
			kind = "NTP request"
		default:
			payload = []byte("pkttrack probe\n")
		}
	}
	start := time.Now()
	if _, err := c.Write(payload); err != nil {
		res.Summary = "UDP send " + describeNetErr(err, r.Timeout)
		return res
	}
	_ = c.SetReadDeadline(start.Add(r.Timeout))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			res.Summary = fmt.Sprintf("sent %s → ICMP port unreachable: nothing is listening", kind)
			return res
		}
		res.Summary = fmt.Sprintf("sent %s (%s), no reply within %s — UDP is silent, so the port is open or filtered", kind, humanBytes(len(payload)), r.Timeout)
		return res
	}
	res.OK, res.RTT = true, time.Since(start)
	res.Summary = fmt.Sprintf("sent %s, got %s reply in %s", kind, humanBytes(n), fmtDur(res.RTT))
	if r.Port == 53 || r.Port == 5353 {
		d := &layers.DNS{}
		if d.DecodeFromBytes(buf[:n], gopacket.NilDecodeFeedback) == nil {
			res.Summary += " · " + dnsSummary(d)
		}
	}
	return res
}

func dnsQuery(name string) []byte {
	d := &layers.DNS{ID: uint16(time.Now().UnixNano()), RD: true,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	buf := gopacket.NewSerializeBuffer()
	_ = d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true})
	return buf.Bytes()
}

func probeICMP(r ProbeReq, seq int) ProbeResult {
	v4 := r.IP.To4() != nil
	// Unprivileged "ping sockets" first (work without root on macOS), raw sockets as fallback.
	nets := []string{"udp6", "ip6:ipv6-icmp"}
	listen, protoNum := "::", 58
	var echoType icmp.Type = ipv6.ICMPTypeEchoRequest
	if v4 {
		nets, listen, protoNum, echoType = []string{"udp4", "ip4:icmp"}, "0.0.0.0", 1, ipv4.ICMPTypeEcho
	}
	var pc *icmp.PacketConn
	var network string
	var err error
	for _, network = range nets {
		if pc, err = icmp.ListenPacket(network, listen); err == nil {
			break
		}
	}
	if err != nil {
		return ProbeResult{Summary: "cannot open ICMP socket: " + err.Error()}
	}
	defer pc.Close()

	msg := icmp.Message{Type: echoType, Body: &icmp.Echo{ID: probeID, Seq: seq, Data: []byte("pkttrack probe")}}
	b, _ := msg.Marshal(nil)
	var dst net.Addr = &net.IPAddr{IP: r.IP}
	if network == "udp4" || network == "udp6" {
		dst = &net.UDPAddr{IP: r.IP}
	}
	start := time.Now()
	if _, err := pc.WriteTo(b, dst); err != nil {
		return ProbeResult{Summary: "ping send " + describeNetErr(err, r.Timeout)}
	}
	_ = pc.SetReadDeadline(start.Add(r.Timeout))
	buf := make([]byte, 1500)
	for {
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			return ProbeResult{Summary: fmt.Sprintf("ping #%d: no reply within %s (host down, or ICMP blocked)", seq, r.Timeout)}
		}
		data := buf[:n]
		if v4 && n > 20 && data[0]>>4 == 4 { // some platforms include the IP header
			data = data[int(data[0]&0x0f)*4:]
		}
		m, err := icmp.ParseMessage(protoNum, data)
		if err != nil {
			continue
		}
		switch m.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			if e, ok := m.Body.(*icmp.Echo); ok && e.Seq != seq {
				continue
			}
			rtt := time.Since(start)
			return ProbeResult{OK: true, RTT: rtt, Summary: fmt.Sprintf("ping #%d: reply from %s in %s", seq, peerIP(peer), fmtDur(rtt))}
		case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
			return ProbeResult{Summary: fmt.Sprintf("ping #%d: destination unreachable (from %s)", seq, peerIP(peer))}
		case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
			return ProbeResult{Summary: fmt.Sprintf("ping #%d: TTL expired at %s", seq, peerIP(peer))}
		}
	}
}

func peerIP(a net.Addr) string {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.IPAddr:
		return v.IP.String()
	}
	return a.String()
}

// ---- building a request from a target ----------------------------------------

// defaultProbe picks sensible probe settings for a target.
func defaultProbe(s *TargetSpec) ProbeReq {
	r := ProbeReq{Count: 1, Timeout: 3 * time.Second}
	if net.ParseIP(s.Host) == nil && len(s.Nets) > 0 {
		if _, _, err := net.ParseCIDR(s.Host); err != nil {
			r.Host = s.Host
		}
	}
	r.IP = defaultProbeIP(s)
	if len(s.Ports) > 0 {
		r.Port = s.Ports[0].Lo
	}
	r.Proto = resolveProbeProto(s.Proto, r.Port)
	if r.Proto == ProtoICMP {
		r.Count = 3
	}
	return r
}

func defaultProbeIP(s *TargetSpec) net.IP {
	var pick *net.IPNet
	for _, n := range s.Nets { // prefer IPv4 for hostnames with both
		if n.IP.To4() != nil {
			pick = n
			break
		}
	}
	if pick == nil && len(s.Nets) > 0 {
		pick = s.Nets[0]
	}
	if pick == nil {
		return nil
	}
	ip := make(net.IP, len(pick.IP))
	copy(ip, pick.IP)
	if ones, bits := pick.Mask.Size(); ones < bits && bits-ones > 1 {
		ip[len(ip)-1]++ // first usable host of a range
	}
	return ip
}

func resolveProbeProto(p Proto, port uint16) Proto {
	switch {
	case p != ProtoAny:
		return p
	case port == 0:
		return ProtoICMP
	case port == 53 || port == 123 || port == 5353:
		return ProtoUDP
	}
	return ProtoTCP
}
