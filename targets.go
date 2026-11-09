package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Proto is the transport protocol a target is restricted to.
type Proto int

const (
	ProtoAny Proto = iota
	ProtoTCP
	ProtoUDP
	ProtoICMP
)

var protoNames = []string{"any", "tcp", "udp", "icmp"}

func (p Proto) String() string {
	if p >= 0 && int(p) < len(protoNames) {
		return protoNames[p]
	}
	return "?"
}

func ParseProto(s string) (Proto, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "any", "all", "*":
		return ProtoAny, nil
	case "tcp":
		return ProtoTCP, nil
	case "udp":
		return ProtoUDP, nil
	case "icmp", "icmp6", "icmpv6", "ping":
		return ProtoICMP, nil
	}
	return ProtoAny, fmt.Errorf("unknown protocol %q (use any, tcp, udp or icmp)", s)
}

type PortRange struct{ Lo, Hi uint16 }

func (r PortRange) String() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(int(r.Lo))
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// TargetSpec describes what to watch: one or more IPs/networks, optional
// ports, and an optional protocol.
type TargetSpec struct {
	Host  string // as the user typed it (IP, CIDR or hostname)
	Nets  []*net.IPNet
	Ports []PortRange // empty = any port
	Proto Proto
}

// ParseTargetLine parses "host[:ports] [proto]", e.g. "8.8.8.8:53 udp".
func ParseTargetLine(line string) (TargetSpec, error) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return TargetSpec{}, fmt.Errorf("empty target")
	}
	if len(f) > 2 {
		return TargetSpec{}, fmt.Errorf("too many fields in %q (want host[:ports] [proto])", line)
	}
	host, ports := SplitHostPorts(f[0])
	proto := ""
	if len(f) == 2 {
		proto = f[1]
	}
	return ParseTarget(host, ports, proto)
}

// SplitHostPorts splits "1.2.3.4:443", "[::1]:22,80" or "10.0.0.0/24:80"
// into host and port parts. Bare IPv6 addresses are returned unchanged.
func SplitHostPorts(s string) (host, ports string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		i := strings.Index(s, "]")
		if i < 0 {
			return s, ""
		}
		host, rest := s[1:i], s[i+1:]
		if strings.HasPrefix(rest, "/") { // [2001:db8::]/32:443
			if j := strings.Index(rest, ":"); j >= 0 {
				return host + rest[:j], rest[j+1:]
			}
			return host + rest, ""
		}
		return host, strings.TrimPrefix(rest, ":")
	}
	if strings.Count(s, ":") == 1 {
		i := strings.Index(s, ":")
		return s[:i], s[i+1:]
	}
	return s, ""
}

func ParseTarget(host, ports, proto string) (TargetSpec, error) {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" {
		return TargetSpec{}, fmt.Errorf("host / IP is required")
	}
	nets, err := resolveHost(host)
	if err != nil {
		return TargetSpec{}, err
	}
	pr, err := ParsePorts(ports)
	if err != nil {
		return TargetSpec{}, err
	}
	p, err := ParseProto(proto)
	if err != nil {
		return TargetSpec{}, err
	}
	if p == ProtoICMP && len(pr) > 0 {
		return TargetSpec{}, fmt.Errorf("ICMP has no ports — leave ports blank")
	}
	return TargetSpec{Host: host, Nets: nets, Ports: pr, Proto: p}, nil
}

func resolveHost(h string) ([]*net.IPNet, error) {
	if strings.Contains(h, "/") {
		_, n, err := net.ParseCIDR(h)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR range %q", h)
		}
		return []*net.IPNet{n}, nil
	}
	if ip := net.ParseIP(h); ip != nil {
		return []*net.IPNet{hostNet(ip)}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %q: %v", h, err)
	}
	var out []*net.IPNet
	seen := map[string]bool{}
	for _, a := range addrs {
		if !seen[a.IP.String()] {
			seen[a.IP.String()] = true
			out = append(out, hostNet(a.IP))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%q resolved to no addresses", h)
	}
	return out, nil
}

func hostNet(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
}

// ParsePorts parses "22,80,443", "8000-8100", "https" or "" (any).
func ParsePorts(s string) ([]PortRange, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" || strings.EqualFold(s, "any") {
		return nil, nil
	}
	var out []PortRange
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err := parsePort(lo)
			if err != nil {
				return nil, err
			}
			b, err := parsePort(hi)
			if err != nil {
				return nil, err
			}
			if a > b {
				a, b = b, a
			}
			out = append(out, PortRange{a, b})
			continue
		}
		p, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		out = append(out, PortRange{p, p})
	}
	return out, nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		if n < 1 || n > 65535 {
			return 0, fmt.Errorf("port %d out of range (1-65535)", n)
		}
		return uint16(n), nil
	}
	for _, network := range []string{"tcp", "udp"} {
		if n, err := net.LookupPort(network, s); err == nil {
			return uint16(n), nil
		}
	}
	return 0, fmt.Errorf("unknown port %q", s)
}

func (s *TargetSpec) PortsString() string {
	if len(s.Ports) == 0 {
		return "*"
	}
	parts := make([]string, len(s.Ports))
	for i, r := range s.Ports {
		parts[i] = r.String()
	}
	return strings.Join(parts, ",")
}

// Label is the compact "host:ports" form shown in the UI.
func (s *TargetSpec) Label() string {
	h := s.Host
	if len(s.Ports) > 0 {
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		h += ":" + s.PortsString()
	}
	return h
}

// String is the canonical line form, parseable by ParseTargetLine.
func (s *TargetSpec) String() string {
	l := s.Label()
	if s.Proto != ProtoAny {
		l += " " + s.Proto.String()
	}
	return l
}

func (s *TargetSpec) SingleHost() bool {
	if len(s.Nets) != 1 {
		return false
	}
	ones, bits := s.Nets[0].Mask.Size()
	return ones == bits
}

func (s *TargetSpec) MatchIP(ip net.IP) bool {
	for _, n := range s.Nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *TargetSpec) MatchPort(p uint16) bool {
	if len(s.Ports) == 0 {
		return true
	}
	for _, r := range s.Ports {
		if p >= r.Lo && p <= r.Hi {
			return true
		}
	}
	return false
}

// Match reports whether ev belongs to this target and whether it is heading
// toward the target (true) or coming from it (false).
func (s *TargetSpec) Match(ev *PacketEvent) (toTarget, ok bool) {
	if s.Proto != ProtoAny && ev.Proto != s.Proto {
		return false, false
	}
	icmp := ev.Proto == ProtoICMP
	if s.MatchIP(ev.DstIP) && (icmp || s.MatchPort(ev.DstPort)) {
		return true, true
	}
	if s.MatchIP(ev.SrcIP) && (icmp || s.MatchPort(ev.SrcPort)) {
		return false, true
	}
	return false, false
}

// BPF returns a kernel filter expression for this target so we only copy
// interesting packets out of the kernel.
func (s *TargetSpec) BPF() string {
	var hs []string
	for _, n := range s.Nets {
		ones, bits := n.Mask.Size()
		if ones == bits {
			hs = append(hs, "host "+n.IP.String())
		} else {
			hs = append(hs, "net "+n.String())
		}
	}
	h := "(" + strings.Join(hs, " or ") + ")"
	var ps []string
	for _, r := range s.Ports {
		if r.Lo == r.Hi {
			ps = append(ps, fmt.Sprintf("port %d", r.Lo))
		} else {
			ps = append(ps, fmt.Sprintf("portrange %d-%d", r.Lo, r.Hi))
		}
	}
	p := "(" + strings.Join(ps, " or ") + ")"
	switch s.Proto {
	case ProtoTCP, ProtoUDP:
		if len(ps) == 0 {
			return h + " and " + s.Proto.String()
		}
		return h + " and " + s.Proto.String() + " and " + p
	case ProtoICMP:
		return h + " and (icmp or icmp6)"
	}
	if len(ps) == 0 {
		return h
	}
	// Keep ICMP for the host too: it carries "port unreachable" and friends.
	return h + " and (" + p + " or icmp or icmp6)"
}

func BuildBPF(specs []TargetSpec) string {
	if len(specs) == 0 {
		return "ip proto 255" // reserved protocol: effectively matches nothing
	}
	parts := make([]string, len(specs))
	for i := range specs {
		parts[i] = "(" + specs[i].BPF() + ")"
	}
	return strings.Join(parts, " or ")
}

// ---- persistence ----------------------------------------------------------

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "pkttrack", "targets.txt")
}

func loadConfig(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

// ifaceDirective marks the line in the targets file that remembers which
// interfaces to capture on, e.g. "@interfaces en0,utun3" or "@interfaces all".
const ifaceDirective = "@interfaces "

func saveConfig(path string, specs []TargetSpec, ifaces string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# pkttrack targets — one per line: host[:ports] [proto]\n")
	if ifaces != "" {
		b.WriteString(ifaceDirective + ifaces + "\n")
	}
	for i := range specs {
		b.WriteString(specs[i].String() + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return err
	}
	// When run via sudo, hand the file back to the real user.
	if uid, err := strconv.Atoi(os.Getenv("SUDO_UID")); err == nil {
		gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
		_ = os.Chown(dir, uid, gid)
		_ = os.Chown(path, uid, gid)
	}
	return nil
}
