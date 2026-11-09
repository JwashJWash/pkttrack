package main

import (
	"encoding/binary"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// demoSource synthesises realistic traffic for the current targets. Packets
// are serialised to real bytes and run through the same decoder as live
// capture, so everything downstream behaves identically.
type demoSource struct {
	events  chan *PacketEvent
	errs    chan error
	mu      sync.Mutex
	specs   []TargetSpec
	done    chan struct{}
	once    sync.Once
	dropped atomic.Uint64
	peer4   net.IP
	peer6   net.IP
}

func NewDemoSource() *demoSource {
	s := &demoSource{
		events: make(chan *PacketEvent, 8192),
		errs:   make(chan error, 4),
		done:   make(chan struct{}),
		peer4:  net.ParseIP("192.168.1.42").To4(),
		peer6:  net.ParseIP("fd00::42"),
	}
	go s.run()
	return s
}

func (s *demoSource) Events() <-chan *PacketEvent { return s.events }
func (s *demoSource) Errors() <-chan error        { return s.errs }
func (s *demoSource) Describe() string            { return "demo (simulated traffic)" }
func (s *demoSource) Dropped() uint64             { return s.dropped.Load() }
func (s *demoSource) Close()                      { s.once.Do(func() { close(s.done) }) }

// Inject simulates the probe instead of touching the real network.
func (s *demoSource) Inject(req ProbeReq, seq int) ProbeResult {
	src := s.peer4
	if req.IP.To4() == nil {
		src = s.peer6
	}
	host := req.Host
	if host == "" {
		host = "example.com"
	}
	switch req.Proto {
	case ProtoTCP:
		go s.tcpSession(src, req.IP, req.Port, host)
	case ProtoUDP:
		go s.udpExchange(src, req.IP, req.Port, host)
	case ProtoICMP:
		go s.ping(src, req.IP)
	}
	time.Sleep(150 * time.Millisecond)
	return ProbeResult{OK: true, Summary: "simulated " + req.Proto.String() + " exchange (demo mode — nothing sent on the network)"}
}
func (s *demoSource) Update(specs []TargetSpec) {
	s.mu.Lock()
	s.specs = append([]TargetSpec(nil), specs...)
	s.mu.Unlock()
}

func (s *demoSource) sleep(d time.Duration) bool {
	select {
	case <-s.done:
		return false
	case <-time.After(d):
		return true
	}
}

func ms(lo, hi int) time.Duration { return time.Duration(lo+rand.IntN(hi-lo+1)) * time.Millisecond }

func (s *demoSource) run() {
	for s.sleep(ms(250, 900)) {
		s.mu.Lock()
		specs := s.specs
		s.mu.Unlock()
		if len(specs) == 0 {
			continue
		}
		go s.scenario(specs[rand.IntN(len(specs))])
	}
}

func (s *demoSource) scenario(sp TargetSpec) {
	dst := pickIP(sp)
	src := s.peer4
	if dst.To4() == nil {
		src = s.peer6
	}
	port := pickPort(sp)
	proto := sp.Proto
	if proto == ProtoAny {
		r := rand.IntN(10)
		switch {
		case port == 53 || port == 123 || (port == 0 && r < 2):
			proto = ProtoUDP
		case port == 0 && r < 4:
			proto = ProtoICMP
		default:
			proto = ProtoTCP
		}
	}
	host := "example.com"
	if net.ParseIP(sp.Host) == nil && !strings.Contains(sp.Host, "/") {
		host = sp.Host
	}
	switch proto {
	case ProtoTCP:
		s.tcpSession(src, dst, port, host)
	case ProtoUDP:
		s.udpExchange(src, dst, port, host)
	case ProtoICMP:
		s.ping(src, dst)
	}
}

func pickIP(sp TargetSpec) net.IP {
	n := sp.Nets[rand.IntN(len(sp.Nets))]
	ones, bits := n.Mask.Size()
	if ones == bits {
		return n.IP
	}
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	if v4 := ip.To4(); v4 != nil {
		size := uint32(1) << (32 - ones)
		off := uint32(0)
		if size > 2 {
			off = 1 + rand.Uint32N(size-2)
		}
		binary.BigEndian.PutUint32(v4, binary.BigEndian.Uint32(v4)+off)
		return v4
	}
	ip[15] = byte(1 + rand.IntN(200))
	return ip
}

func pickPort(sp TargetSpec) uint16 {
	if len(sp.Ports) == 0 {
		return 0
	}
	r := sp.Ports[rand.IntN(len(sp.Ports))]
	return r.Lo + uint16(rand.IntN(int(r.Hi-r.Lo)+1))
}

func ephemeral() uint16 { return uint16(49152 + rand.IntN(16000)) }

var (
	macA = net.HardwareAddr{0x02, 0x00, 0x00, 0xaa, 0xbb, 0x01}
	macB = net.HardwareAddr{0x02, 0x00, 0x00, 0xcc, 0xdd, 0x02}
)

func (s *demoSource) emit(src, dst net.IP, proto layers.IPProtocol, ls ...gopacket.SerializableLayer) {
	data := buildPacket(src, dst, proto, src.Equal(s.peer4) || src.Equal(s.peer6), ls...)
	if data == nil {
		return
	}
	ev := decodePacket(data, layers.LinkTypeEthernet, time.Now(), len(data))
	if ev == nil {
		return
	}
	ev.Iface = "demo"
	select {
	case s.events <- ev:
	default:
		s.dropped.Add(1)
	}
}

func buildPacket(src, dst net.IP, proto layers.IPProtocol, fromPeer bool, ls ...gopacket.SerializableLayer) []byte {
	eth := &layers.Ethernet{SrcMAC: macA, DstMAC: macB}
	if !fromPeer {
		eth.SrcMAC, eth.DstMAC = macB, macA
	}
	ttl := uint8(64)
	if !fromPeer {
		ttl = uint8(50 + rand.IntN(8))
	}
	var nl gopacket.NetworkLayer
	all := []gopacket.SerializableLayer{eth}
	if dst.To4() != nil {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip := &layers.IPv4{Version: 4, TTL: ttl, Protocol: proto, SrcIP: src.To4(), DstIP: dst.To4(),
			Id: uint16(rand.IntN(65536)), Flags: layers.IPv4DontFragment}
		nl = ip
		all = append(all, ip)
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: ttl, NextHeader: proto, SrcIP: src, DstIP: dst}
		nl = ip
		all = append(all, ip)
	}
	for _, l := range ls {
		if c, ok := l.(interface {
			SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
		}); ok {
			_ = c.SetNetworkLayerForChecksum(nl)
		}
	}
	all = append(all, ls...)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, all...); err != nil {
		return nil
	}
	return buf.Bytes()
}

// ---- TCP --------------------------------------------------------------------

type tcpSim struct {
	s          *demoSource
	cIP, sIP   net.IP
	cPort      uint16
	sPort      uint16
	cSeq, sSeq uint32
	cWin, sWin uint16
}

func (c *tcpSim) send(fromClient bool, f TCPFlags, payload []byte) {
	seq := c.sSeq
	if fromClient {
		seq = c.cSeq
	}
	c.sendAt(fromClient, f, payload, seq)
	n := uint32(len(payload))
	if f&(FlagSYN|FlagFIN) != 0 {
		n++
	}
	if fromClient {
		c.cSeq += n
	} else {
		c.sSeq += n
	}
}

func (c *tcpSim) sendAt(fromClient bool, f TCPFlags, payload []byte, seq uint32) {
	t := &layers.TCP{Seq: seq, SYN: f&FlagSYN != 0, ACK: f&FlagACK != 0, FIN: f&FlagFIN != 0,
		RST: f&FlagRST != 0, PSH: f&FlagPSH != 0}
	src, dst := c.sIP, c.cIP
	t.SrcPort, t.DstPort, t.Window = layers.TCPPort(c.sPort), layers.TCPPort(c.cPort), c.sWin
	if t.ACK {
		t.Ack = c.cSeq
	}
	if fromClient {
		src, dst = c.cIP, c.sIP
		t.SrcPort, t.DstPort, t.Window = layers.TCPPort(c.cPort), layers.TCPPort(c.sPort), c.cWin
		if t.ACK {
			t.Ack = c.sSeq
		}
	}
	if t.SYN {
		t.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{6}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		}
	}
	ls := []gopacket.SerializableLayer{t}
	if len(payload) > 0 {
		ls = append(ls, gopacket.Payload(payload))
	}
	c.s.emit(src, dst, layers.IPProtocolTCP, ls...)
}

func (s *demoSource) tcpSession(cli, srv net.IP, port uint16, host string) {
	if port == 0 {
		port = []uint16{443, 443, 80, 22}[rand.IntN(4)]
	}
	c := &tcpSim{s: s, cIP: cli, sIP: srv, cPort: ephemeral(), sPort: port,
		cSeq: rand.Uint32(), sSeq: rand.Uint32(), cWin: 65535, sWin: 64240}
	rtt := ms(8, 70)
	half := rtt / 2

	c.send(true, FlagSYN, nil)
	if rand.IntN(100) < 10 { // nothing listening
		s.sleep(half)
		c.sendAt(false, FlagRST|FlagACK, nil, 0)
		return
	}
	if rand.IntN(100) < 5 { // SYN lost, retried
		s.sleep(time.Second)
		c.cSeq--
		c.send(true, FlagSYN, nil)
	}
	s.sleep(half)
	c.send(false, FlagSYN|FlagACK, nil)
	s.sleep(half)
	c.send(true, FlagACK, nil)

	req, resp := appPayloads(port, host)
	s.sleep(ms(1, 5))
	reqSeq := c.cSeq
	c.send(true, FlagPSH|FlagACK, req)
	if rand.IntN(100) < 12 { // lost request → retransmission
		s.sleep(rtt * 3)
		c.sendAt(true, FlagPSH|FlagACK, req, reqSeq)
	}
	s.sleep(half)
	c.send(false, FlagACK, nil)
	s.sleep(ms(2, 20))
	c.send(false, FlagPSH|FlagACK, resp)
	s.sleep(half)
	c.send(true, FlagACK, nil)

	for i := rand.IntN(5); i > 0; i-- {
		if !s.sleep(ms(80, 600)) {
			return
		}
		c.send(true, FlagPSH|FlagACK, appData(port, 40+rand.IntN(300)))
		s.sleep(half)
		for j := rand.IntN(3) + 1; j > 0; j-- {
			c.send(false, FlagACK, appData(port, 1000+rand.IntN(448)))
			s.sleep(ms(1, 4))
		}
		if rand.IntN(100) < 5 { // receiver buffer full
			c.cWin = 0
			c.send(true, FlagACK, nil)
			s.sleep(ms(200, 500))
			c.cWin = 65535
		}
		c.send(true, FlagACK, nil)
	}
	s.sleep(ms(100, 800))
	if rand.IntN(100) < 10 {
		c.send(true, FlagRST|FlagACK, nil)
		return
	}
	c.send(true, FlagFIN|FlagACK, nil)
	s.sleep(half)
	c.send(false, FlagACK, nil)
	c.send(false, FlagFIN|FlagACK, nil)
	s.sleep(half)
	c.send(true, FlagACK, nil)
}

func appPayloads(port uint16, host string) ([]byte, []byte) {
	switch port {
	case 443, 8443:
		return fakeClientHello(host), tlsRecord(22, append([]byte{2, 0, 0, 70, 3, 3}, randBytes(66)...))
	case 80, 8080:
		return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: pkttrack-demo\r\nAccept: */*\r\n\r\n"),
			[]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 180\r\n\r\n<html><body>" + strings.Repeat("hello ", 26) + "</body></html>")
	case 22:
		return []byte("SSH-2.0-OpenSSH_9.8\r\n"), []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
	}
	return randBytes(64 + rand.IntN(200)), randBytes(200 + rand.IntN(800))
}

func appData(port uint16, n int) []byte {
	if port == 443 || port == 8443 {
		return tlsRecord(23, randBytes(n))
	}
	return randBytes(n)
}

func tlsRecord(typ byte, body []byte) []byte {
	return append([]byte{typ, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

func fakeClientHello(sni string) []byte {
	name := []byte(sni)
	u16 := func(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
	sniList := append(append([]byte{0}, u16(len(name))...), name...)
	sniExt := append(append(append([]byte{0, 0}, u16(len(sniList)+2)...), u16(len(sniList))...), sniList...)
	var hello []byte
	hello = append(hello, 3, 3)
	hello = append(hello, randBytes(32)...)
	hello = append(hello, 0)                            // session id
	hello = append(hello, 0, 4, 0x13, 0x01, 0x13, 0x02) // cipher suites
	hello = append(hello, 1, 0)                         // compression
	hello = append(append(hello, u16(len(sniExt))...), sniExt...)
	hs := append([]byte{1, 0, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	return tlsRecord(22, hs)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.IntN(256))
	}
	return b
}

// ---- UDP / ICMP -----------------------------------------------------------------

var demoNames = []string{"example.com", "github.com", "api.stripe.com", "news.ycombinator.com", "does-not-exist.invalid"}

func (s *demoSource) udpExchange(cli, srv net.IP, port uint16, host string) {
	sp := ephemeral()
	rtt := ms(5, 60)
	if port == 0 || port == 53 {
		port = 53
		name := demoNames[rand.IntN(len(demoNames))]
		if host != "example.com" && rand.IntN(2) == 0 {
			name = host
		}
		id := uint16(rand.IntN(65536))
		q := layers.DNSQuestion{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
		s.emit(cli, srv, layers.IPProtocolUDP, &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: 53},
			&layers.DNS{ID: id, RD: true, Questions: []layers.DNSQuestion{q}})
		s.sleep(rtt)
		resp := &layers.DNS{ID: id, QR: true, RD: true, RA: true, Questions: []layers.DNSQuestion{q}}
		if strings.HasSuffix(name, ".invalid") {
			resp.ResponseCode = layers.DNSResponseCodeNXDomain
		} else {
			for i := rand.IntN(2) + 1; i > 0; i-- {
				resp.Answers = append(resp.Answers, layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypeA,
					Class: layers.DNSClassIN, TTL: 300, IP: net.IPv4(93, 184, byte(rand.IntN(256)), byte(rand.IntN(256)))})
			}
		}
		s.emit(srv, cli, layers.IPProtocolUDP, &layers.UDP{SrcPort: 53, DstPort: layers.UDPPort(sp)}, resp)
		return
	}
	closed := rand.IntN(100) < 25
	for i := 0; i < 1+rand.IntN(3); i++ {
		u := &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(port)}
		p := randBytes(20 + rand.IntN(300))
		s.emit(cli, srv, layers.IPProtocolUDP, u, gopacket.Payload(p))
		s.sleep(rtt)
		if closed { // nobody listening: the host answers with ICMP port unreachable
			orig := buildPacket(cli, srv, layers.IPProtocolUDP, true, &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(port)}, gopacket.Payload(p))
			quote := orig[14:min(len(orig), 14+48)]
			if srv.To4() != nil {
				s.emit(srv, cli, layers.IPProtocolICMPv4, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 3)}, gopacket.Payload(quote))
			} else {
				s.emit(srv, cli, layers.IPProtocolICMPv6, &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(1, 4)}, gopacket.Payload(append(make([]byte, 4), quote...)))
			}
			return
		}
		s.emit(srv, cli, layers.IPProtocolUDP, &layers.UDP{SrcPort: layers.UDPPort(port), DstPort: layers.UDPPort(sp)}, gopacket.Payload(randBytes(20+rand.IntN(600))))
		s.sleep(ms(50, 300))
	}
}

func (s *demoSource) ping(cli, srv net.IP) {
	id := uint16(rand.IntN(65536))
	rtt := ms(5, 80)
	lossy := rand.IntN(100) < 20
	body := []byte("pkttrack-demo-ping-payload-abcdefghijklmnop")
	for seq := uint16(0); seq < uint16(2+rand.IntN(3)); seq++ {
		v4 := srv.To4() != nil
		if v4 {
			s.emit(cli, srv, layers.IPProtocolICMPv4, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: id, Seq: seq}, gopacket.Payload(body))
		} else {
			s.emit(cli, srv, layers.IPProtocolICMPv6, &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)},
				&layers.ICMPv6Echo{Identifier: id, SeqNumber: seq}, gopacket.Payload(body))
		}
		if !s.sleep(rtt + ms(0, 10)) {
			return
		}
		if !(lossy && rand.IntN(2) == 0) {
			if v4 {
				s.emit(srv, cli, layers.IPProtocolICMPv4, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(0, 0), Id: id, Seq: seq}, gopacket.Payload(body))
			} else {
				s.emit(srv, cli, layers.IPProtocolICMPv6, &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(129, 0)},
					&layers.ICMPv6Echo{Identifier: id, SeqNumber: seq}, gopacket.Payload(body))
			}
		}
		if !s.sleep(ms(300, 600)) {
			return
		}
	}
}
