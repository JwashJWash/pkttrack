package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const rawKeep = 512

func decodePacket(data []byte, dec gopacket.Decoder, ts time.Time, wireLen int) *PacketEvent {
	pkt := gopacket.NewPacket(data, dec, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ev := &PacketEvent{Time: ts, Size: wireLen, Link: dec}
	if ev.Size == 0 {
		ev.Size = len(data)
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	switch ip := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		ev.IPVer, ev.SrcIP, ev.DstIP, ev.TTL = 4, ip.SrcIP, ip.DstIP, ip.TTL
	case *layers.IPv6:
		ev.IPVer, ev.SrcIP, ev.DstIP, ev.TTL = 6, ip.SrcIP, ip.DstIP, ip.HopLimit
	default:
		return nil
	}

	if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
		t := l.(*layers.TCP)
		ev.Proto = ProtoTCP
		ev.SrcPort, ev.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
		ev.Seq, ev.Ack, ev.Window = t.Seq, t.Ack, t.Window
		ev.Flags = tcpFlags(t)
		ev.Payload = len(t.Payload)
		ev.App, ev.Info = sniffTCP(t.Payload, ev.SrcPort, ev.DstPort)
	} else if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
		u := l.(*layers.UDP)
		ev.Proto = ProtoUDP
		ev.SrcPort, ev.DstPort = uint16(u.SrcPort), uint16(u.DstPort)
		ev.Payload = len(u.Payload)
		ev.App, ev.Info = sniffUDP(pkt, u)
	} else if l := pkt.Layer(layers.LayerTypeICMPv4); l != nil {
		ic := l.(*layers.ICMPv4)
		ev.Proto = ProtoICMP
		ev.ICMPType, ev.ICMPCode = ic.TypeCode.Type(), ic.TypeCode.Code()
		ev.ICMPID, ev.ICMPSeq = ic.Id, ic.Seq
		ev.Payload = len(ic.Payload)
		ev.App, ev.Info = "ICMP", icmpDesc(4, ev.ICMPType, ev.ICMPCode)
	} else if l := pkt.Layer(layers.LayerTypeICMPv6); l != nil {
		ic := l.(*layers.ICMPv6)
		ev.Proto = ProtoICMP
		ev.ICMPType, ev.ICMPCode = ic.TypeCode.Type(), ic.TypeCode.Code()
		if e := pkt.Layer(layers.LayerTypeICMPv6Echo); e != nil {
			ec := e.(*layers.ICMPv6Echo)
			ev.ICMPID, ev.ICMPSeq = ec.Identifier, ec.SeqNumber
		}
		ev.Payload = len(ic.Payload)
		ev.App, ev.Info = "ICMP", icmpDesc(6, ev.ICMPType, ev.ICMPCode)
	} else {
		return nil
	}

	if nl := pkt.NetworkLayer(); nl != nil {
		h := fnv.New64a()
		h.Write(nl.LayerContents())
		pl := nl.LayerPayload()
		h.Write(pl[:min(len(pl), 64)])
		ev.Sig = h.Sum64()
	}
	n := len(data)
	if n > rawKeep {
		n = rawKeep
	}
	ev.Raw = data[:n]
	return ev
}

func tcpFlags(t *layers.TCP) TCPFlags {
	var f TCPFlags
	set := func(b bool, x TCPFlags) {
		if b {
			f |= x
		}
	}
	set(t.FIN, FlagFIN)
	set(t.SYN, FlagSYN)
	set(t.RST, FlagRST)
	set(t.PSH, FlagPSH)
	set(t.ACK, FlagACK)
	set(t.URG, FlagURG)
	set(t.ECE, FlagECE)
	set(t.CWR, FlagCWR)
	return f
}

// ---- ICMP -----------------------------------------------------------------

func icmpDesc(ver int, typ, code uint8) string {
	if ver == 4 {
		switch typ {
		case 0:
			return "echo reply"
		case 3:
			names := map[uint8]string{0: "network unreachable", 1: "host unreachable", 2: "protocol unreachable",
				3: "port unreachable", 4: "fragmentation needed", 9: "network prohibited", 10: "host prohibited",
				13: "administratively prohibited"}
			if n, ok := names[code]; ok {
				return "dest unreachable: " + n
			}
			return fmt.Sprintf("dest unreachable (code %d)", code)
		case 5:
			return "redirect"
		case 8:
			return "echo request"
		case 11:
			if code == 0 {
				return "time exceeded: TTL expired in transit"
			}
			return "time exceeded: fragment reassembly"
		case 12:
			return "parameter problem"
		}
		return fmt.Sprintf("type %d code %d", typ, code)
	}
	switch typ {
	case 1:
		names := map[uint8]string{0: "no route", 1: "administratively prohibited", 3: "address unreachable", 4: "port unreachable"}
		if n, ok := names[code]; ok {
			return "dest unreachable: " + n
		}
		return fmt.Sprintf("dest unreachable (code %d)", code)
	case 2:
		return "packet too big"
	case 3:
		return "time exceeded: hop limit expired"
	case 4:
		return "parameter problem"
	case 128:
		return "echo request"
	case 129:
		return "echo reply"
	case 133:
		return "router solicitation"
	case 134:
		return "router advertisement"
	case 135:
		return "neighbor solicitation"
	case 136:
		return "neighbor advertisement"
	}
	return fmt.Sprintf("type %d code %d", typ, code)
}

func isEchoReq(ev *PacketEvent) bool {
	return (ev.IPVer == 4 && ev.ICMPType == 8) || (ev.IPVer == 6 && ev.ICMPType == 128)
}
func isEchoReply(ev *PacketEvent) bool {
	return (ev.IPVer == 4 && ev.ICMPType == 0) || (ev.IPVer == 6 && ev.ICMPType == 129)
}
func isICMPError(ev *PacketEvent) bool {
	if ev.IPVer == 4 {
		return ev.ICMPType == 3 || ev.ICMPType == 11 || ev.ICMPType == 12
	}
	return ev.ICMPType >= 1 && ev.ICMPType <= 4
}

// ---- application-layer sniffing --------------------------------------------

var httpMethods = [][]byte{[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT ")}

func sniffTCP(p []byte, sp, dp uint16) (string, string) {
	if len(p) == 0 {
		return "", ""
	}
	if len(p) >= 5 && p[1] == 3 && p[0] >= 20 && p[0] <= 23 {
		switch p[0] {
		case 20:
			return "TLS", "TLS ChangeCipherSpec"
		case 21:
			return "TLS", "TLS Alert"
		case 22:
			if len(p) > 5 {
				switch p[5] {
				case 1:
					if sni := parseSNI(p); sni != "" {
						return "TLS", "TLS ClientHello SNI=" + sni
					}
					return "TLS", "TLS ClientHello"
				case 2:
					return "TLS", "TLS ServerHello"
				case 11:
					return "TLS", "TLS Certificate"
				}
			}
			return "TLS", "TLS Handshake"
		case 23:
			return "TLS", "TLS Application Data (encrypted)"
		}
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(p, m) {
			return "HTTP", firstLine(p)
		}
	}
	if bytes.HasPrefix(p, []byte("HTTP/1.")) {
		return "HTTP", firstLine(p)
	}
	if bytes.HasPrefix(p, []byte("SSH-")) {
		return "SSH", firstLine(p)
	}
	if sp == 22 || dp == 22 {
		return "SSH", "SSH (encrypted)"
	}
	return "", ""
}

func firstLine(p []byte) string {
	if i := bytes.IndexAny(p, "\r\n"); i >= 0 {
		p = p[:i]
	}
	if len(p) > 80 {
		p = p[:80]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return '.'
		}
		return r
	}, string(p))
}

// parseSNI pulls the server name out of a TLS ClientHello record.
func parseSNI(p []byte) string {
	if len(p) < 5+4+34 {
		return ""
	}
	b := p[5:]
	if b[0] != 1 {
		return ""
	}
	b = b[4+34:] // handshake header, client version, random
	skip := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		n := int(b[0])
		if lenBytes == 2 {
			n = int(binary.BigEndian.Uint16(b))
		}
		b = b[lenBytes:]
		if len(b) < n {
			return false
		}
		b = b[n:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return ""
	}
	if len(b) < 2 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) > n {
		b = b[:n]
	}
	for len(b) >= 4 {
		typ, l := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if len(b) < l {
			return ""
		}
		if typ == 0 { // server_name
			e := b[:l]
			if len(e) < 5 || e[2] != 0 {
				return ""
			}
			nl := int(binary.BigEndian.Uint16(e[3:]))
			e = e[5:]
			if len(e) < nl {
				return ""
			}
			return string(e[:nl])
		}
		b = b[l:]
	}
	return ""
}

func sniffUDP(pkt gopacket.Packet, u *layers.UDP) (string, string) {
	if l := pkt.Layer(layers.LayerTypeDNS); l != nil {
		return "DNS", dnsSummary(l.(*layers.DNS))
	}
	sp, dp := uint16(u.SrcPort), uint16(u.DstPort)
	p := u.Payload
	switch {
	case (sp == 443 || dp == 443) && len(p) > 0:
		if p[0]&0x80 != 0 {
			names := [...]string{"Initial", "0-RTT", "Handshake", "Retry"}
			return "QUIC", "QUIC long header (" + names[(p[0]>>4)&3] + ")"
		}
		return "QUIC", "QUIC short header (encrypted data)"
	case sp == 123 || dp == 123:
		return "NTP", "NTP time sync"
	case sp == 67 || dp == 67 || sp == 68 || dp == 68:
		return "DHCP", "DHCP"
	}
	return "", ""
}

func dnsSummary(d *layers.DNS) string {
	q := "?"
	if len(d.Questions) > 0 {
		q = fmt.Sprintf("%s %s", d.Questions[0].Type, string(d.Questions[0].Name))
	}
	if !d.QR {
		return "DNS query " + q
	}
	if d.ResponseCode != layers.DNSResponseCodeNoErr {
		return fmt.Sprintf("DNS reply %s → %s", q, d.ResponseCode)
	}
	var ans []string
	for _, a := range d.Answers {
		switch a.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			ans = append(ans, a.IP.String())
		case layers.DNSTypeCNAME:
			ans = append(ans, "CNAME "+string(a.CNAME))
		}
		if len(ans) == 3 {
			ans = append(ans, "…")
			break
		}
	}
	if len(ans) == 0 {
		return "DNS reply " + q + " (no answers)"
	}
	return "DNS reply " + q + " → " + strings.Join(ans, ", ")
}

// ---- inspector --------------------------------------------------------------

func inspectLines(lp *LoggedPacket) []string {
	ev := lp.Ev
	out := []string{
		"WHAT IT'S DOING",
		"  " + lp.Explain,
	}
	if lp.Note != "" {
		out = append(out, "  note: "+lp.Note)
	}
	out = append(out, "", "LAYERS")
	pkt := gopacket.NewPacket(ev.Raw, ev.Link, gopacket.Default)
	pad := "             "
	for _, l := range pkt.Layers() {
		switch v := l.(type) {
		case *layers.Ethernet:
			out = append(out, fmt.Sprintf("  Ethernet   %s → %s  type %s", v.SrcMAC, v.DstMAC, v.EthernetType))
		case *layers.Loopback:
			out = append(out, fmt.Sprintf("  Loopback   family %s", v.Family))
		case *layers.IPv4:
			out = append(out, fmt.Sprintf("  IPv4       %s → %s", v.SrcIP, v.DstIP),
				fmt.Sprintf("%sTTL %d  ID 0x%04x  total len %d  flags %s  frag off %d  proto %s  csum 0x%04x",
					pad, v.TTL, v.Id, v.Length, v.Flags, v.FragOffset, v.Protocol, v.Checksum))
		case *layers.IPv6:
			out = append(out, fmt.Sprintf("  IPv6       %s → %s", v.SrcIP, v.DstIP),
				fmt.Sprintf("%shop limit %d  payload len %d  next %s  class %d  flow 0x%05x",
					pad, v.HopLimit, v.Length, v.NextHeader, v.TrafficClass, v.FlowLabel))
		case *layers.TCP:
			out = append(out, fmt.Sprintf("  TCP        port %d → %d   flags [%s]", v.SrcPort, v.DstPort, tcpFlags(v)),
				fmt.Sprintf("%sseq %d (abs %d)   ack %d (abs %d)", pad, lp.RelSeq, v.Seq, lp.RelAck, v.Ack),
				fmt.Sprintf("%swindow %d   payload %d bytes   csum 0x%04x   urg %d", pad, v.Window, len(v.Payload), v.Checksum, v.Urgent))
			if o := tcpOpts(v.Options); o != "" {
				out = append(out, pad+"options "+o)
			}
		case *layers.UDP:
			out = append(out, fmt.Sprintf("  UDP        port %d → %d   len %d   csum 0x%04x", v.SrcPort, v.DstPort, v.Length, v.Checksum))
		case *layers.ICMPv4:
			out = append(out, fmt.Sprintf("  ICMPv4     %s   id %d  seq %d", icmpDesc(4, v.TypeCode.Type(), v.TypeCode.Code()), v.Id, v.Seq))
		case *layers.ICMPv6:
			out = append(out, fmt.Sprintf("  ICMPv6     %s", icmpDesc(6, v.TypeCode.Type(), v.TypeCode.Code())))
		case *layers.ICMPv6Echo:
			out = append(out, fmt.Sprintf("  ICMPv6Echo id %d  seq %d", v.Identifier, v.SeqNumber))
		case *layers.DNS:
			out = append(out, fmt.Sprintf("  DNS        id 0x%04x  %s  rcode %s  %d question(s)  %d answer(s)",
				v.ID, map[bool]string{false: "query", true: "response"}[v.QR], v.ResponseCode, len(v.Questions), len(v.Answers)))
			for _, q := range v.Questions {
				out = append(out, fmt.Sprintf("%s? %s %s", pad, q.Type, q.Name))
			}
			for _, a := range v.Answers {
				val := a.IP.String()
				if a.Type == layers.DNSTypeCNAME {
					val = string(a.CNAME)
				}
				out = append(out, fmt.Sprintf("%s= %s %s %s ttl %d", pad, a.Type, a.Name, val, a.TTL))
			}
		case gopacket.Payload:
			desc := ""
			if ev.Info != "" {
				desc = "   (" + ev.Info + ")"
			}
			out = append(out, fmt.Sprintf("  Payload    %d bytes%s", len(v), desc))
		case *gopacket.DecodeFailure:
			out = append(out, fmt.Sprintf("  (undecoded %d bytes)", len(v.LayerContents())))
		default:
			out = append(out, fmt.Sprintf("  %-10s %d bytes", l.LayerType(), len(l.LayerContents())))
		}
	}
	out = append(out, "", fmt.Sprintf("HEX DUMP  (%d of %d bytes captured)  interface %s  %s",
		len(ev.Raw), ev.Size, ev.Iface, ev.Time.Format("15:04:05.000000")))
	out = append(out, hexDump(ev.Raw)...)
	return out
}

func tcpOpts(opts []layers.TCPOption) string {
	var s []string
	for _, o := range opts {
		switch o.OptionType {
		case layers.TCPOptionKindNop, layers.TCPOptionKindEndList:
		case layers.TCPOptionKindMSS:
			if len(o.OptionData) == 2 {
				s = append(s, fmt.Sprintf("MSS=%d", binary.BigEndian.Uint16(o.OptionData)))
			}
		case layers.TCPOptionKindWindowScale:
			if len(o.OptionData) == 1 {
				s = append(s, fmt.Sprintf("WScale=%d", o.OptionData[0]))
			}
		case layers.TCPOptionKindSACKPermitted:
			s = append(s, "SACK-permitted")
		case layers.TCPOptionKindSACK:
			s = append(s, "SACK")
		case layers.TCPOptionKindTimestamps:
			if len(o.OptionData) == 8 {
				s = append(s, fmt.Sprintf("TS=%d/%d", binary.BigEndian.Uint32(o.OptionData), binary.BigEndian.Uint32(o.OptionData[4:])))
			}
		default:
			s = append(s, o.OptionType.String())
		}
	}
	return strings.Join(s, "  ")
}

func hexDump(b []byte) []string {
	var out []string
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		var hx, asc strings.Builder
		for i := off; i < off+16; i++ {
			if i == off+8 {
				hx.WriteByte(' ')
			}
			if i < end {
				fmt.Fprintf(&hx, "%02x ", b[i])
				c := b[i]
				if c < 32 || c > 126 {
					c = '.'
				}
				asc.WriteByte(c)
			} else {
				hx.WriteString("   ")
			}
		}
		out = append(out, fmt.Sprintf("  %04x  %s %s", off, hx.String(), asc.String()))
	}
	return out
}
