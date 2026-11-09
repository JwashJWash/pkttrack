package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

type TCPFlags uint8

const (
	FlagFIN TCPFlags = 1 << iota
	FlagSYN
	FlagRST
	FlagPSH
	FlagACK
	FlagURG
	FlagECE
	FlagCWR
)

var flagOrder = []struct {
	f TCPFlags
	n string
}{{FlagSYN, "SYN"}, {FlagFIN, "FIN"}, {FlagRST, "RST"}, {FlagPSH, "PSH"}, {FlagACK, "ACK"}, {FlagURG, "URG"}, {FlagECE, "ECE"}, {FlagCWR, "CWR"}}

func (f TCPFlags) String() string {
	var s []string
	for _, x := range flagOrder {
		if f&x.f != 0 {
			s = append(s, x.n)
		}
	}
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ",")
}

// PacketEvent is a decoded packet, independent of where it came from.
type PacketEvent struct {
	Time             time.Time
	Iface            string
	Proto            Proto
	IPVer            int
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	TTL              uint8
	Size             int // bytes on the wire
	Payload          int // transport payload bytes

	Flags    TCPFlags
	Seq, Ack uint32
	Window   uint16

	ICMPType, ICMPCode uint8
	ICMPID, ICMPSeq    uint16

	App  string // short app-protocol tag: TLS, HTTP, DNS, SSH, QUIC...
	Info string // human summary of the app payload

	Sig  uint64           // hash of the IP packet, to drop cross-interface duplicates
	Raw  []byte           // first bytes of the frame, for the inspector
	Link gopacket.Decoder // link-layer decoder for Raw
}

// Source produces PacketEvents. It is either a live pcap capture or the demo
// traffic generator.
type Source interface {
	Events() <-chan *PacketEvent
	Errors() <-chan error
	Update(specs []TargetSpec)
	Describe() string
	Dropped() uint64
	Close()
}

// ---- live capture ---------------------------------------------------------

// ifaceSource is implemented by sources whose capture interfaces can be
// changed while running.
type ifaceSource interface {
	Interfaces() []string
	SetInterfaces(names []string) (opened []string, failed map[string]error)
	IfaceCount(name string) uint64
}

type ifaceReader struct {
	name   string
	handle *pcap.Handle
	filter chan string
	done   chan struct{}
	pkts   atomic.Uint64
}

type seenPkt struct {
	at    time.Time
	iface string
}

type pcapSource struct {
	events  chan *PacketEvent
	errs    chan error
	dropped atomic.Uint64
	done    chan struct{}
	once    sync.Once

	snaplen int
	promisc bool

	mu      sync.Mutex
	readers map[string]*ifaceReader
	filter  string
	counts  map[string]uint64 // packets seen per interface, kept after removal

	seenMu sync.Mutex
	seen   map[uint64]seenPkt
}

// OpenPcap starts capturing on the named interfaces. An empty list means the
// default-route interface; "all" means every interface that is up and has an
// address.
func OpenPcap(names []string, snaplen int, promisc bool) (*pcapSource, []string, error) {
	s := &pcapSource{
		events:  make(chan *PacketEvent, 8192),
		errs:    make(chan error, 16),
		done:    make(chan struct{}),
		snaplen: snaplen,
		promisc: promisc,
		readers: map[string]*ifaceReader{},
		filter:  BuildBPF(nil),
		counts:  map[string]uint64{},
		seen:    map[uint64]seenPkt{},
	}
	names, err := ExpandInterfaces(names)
	if err != nil {
		return nil, nil, err
	}
	opened, failed := s.SetInterfaces(names)
	if len(opened) == 0 {
		var msgs []string
		for n, e := range failed {
			msgs = append(msgs, n+": "+e.Error())
		}
		sort.Strings(msgs)
		return nil, nil, fmt.Errorf("could not open any interface: %s", strings.Join(msgs, "; "))
	}
	var warns []string
	for n, e := range failed {
		warns = append(warns, fmt.Sprintf("skipped %s (%v)", n, e))
	}
	sort.Strings(warns)
	return s, warns, nil
}

// ExpandInterfaces resolves "" (default) and "all" into concrete names.
func ExpandInterfaces(names []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, n := range names {
		n = strings.TrimSpace(n)
		switch strings.ToLower(n) {
		case "":
		case "all", "any", "*":
			devs, err := ListDevices()
			if err != nil {
				return nil, err
			}
			for _, d := range devs {
				if d.Active() {
					add(d.Name)
				}
			}
		default:
			add(n)
		}
	}
	if len(out) == 0 {
		n, err := defaultInterface()
		if err != nil {
			return nil, err
		}
		out = []string{n}
	}
	return out, nil
}

// SetInterfaces makes the capture run on exactly these interfaces, opening
// new ones and stopping removed ones. Already-open interfaces keep running.
func (s *pcapSource) SetInterfaces(names []string) ([]string, map[string]error) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	failed := map[string]error{}
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, r := range s.readers {
		if !want[n] {
			close(r.done) // the reader goroutine closes its own handle
			delete(s.readers, n)
		}
	}
	for _, n := range names {
		if _, ok := s.readers[n]; ok {
			continue
		}
		h, err := openHandle(n, s.snaplen, s.promisc)
		if err != nil {
			failed[n] = err
			continue
		}
		if err := h.SetBPFFilter(s.filter); err != nil {
			s.sendErr(fmt.Errorf("%s: BPF filter rejected: %v", n, err))
		}
		r := &ifaceReader{name: n, handle: h, filter: make(chan string, 1), done: make(chan struct{})}
		s.readers[n] = r
		go s.loop(r)
	}
	var opened []string
	for n := range s.readers {
		opened = append(opened, n)
	}
	sort.Strings(opened)
	return opened, failed
}

func (s *pcapSource) Interfaces() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.readers))
	for n := range s.readers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (s *pcapSource) IfaceCount(name string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.counts[name]
	if r, ok := s.readers[name]; ok {
		c += r.pkts.Load()
	}
	return c
}

func openHandle(name string, snaplen int, promisc bool) (*pcap.Handle, error) {
	in, err := pcap.NewInactiveHandle(name)
	if err != nil {
		return nil, err
	}
	defer in.CleanUp()
	_ = in.SetSnapLen(snaplen)
	_ = in.SetPromisc(promisc)
	_ = in.SetTimeout(200 * time.Millisecond)
	_ = in.SetImmediateMode(true) // deliver packets as they arrive, not in batches
	return in.Activate()
}

func (s *pcapSource) loop(r *ifaceReader) {
	defer func() {
		s.mu.Lock()
		s.counts[r.name] += r.pkts.Load()
		s.mu.Unlock()
		r.handle.Close()
	}()
	lt := r.handle.LinkType()
	for {
		select {
		case <-s.done:
			return
		case <-r.done:
			return
		case f := <-r.filter:
			if err := r.handle.SetBPFFilter(f); err != nil {
				s.sendErr(fmt.Errorf("%s: BPF filter rejected: %v", r.name, err))
			}
		default:
		}
		data, ci, err := r.handle.ReadPacketData()
		if err != nil {
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			if errors.Is(err, io.EOF) || err == pcap.NextErrorNoMorePackets {
				return
			}
			select {
			case <-s.done:
				return
			case <-r.done:
				return
			default:
			}
			s.sendErr(fmt.Errorf("%s: read: %v (interface down? press i to change interfaces)", r.name, err))
			time.Sleep(time.Second)
			continue
		}
		ev := decodePacket(data, lt, ci.Timestamp, ci.Length)
		if ev == nil {
			continue
		}
		ev.Iface = r.name
		if s.duplicate(ev) {
			continue
		}
		r.pkts.Add(1)
		select {
		case s.events <- ev:
		default:
			s.dropped.Add(1)
		}
	}
}

// duplicate reports whether the same IP packet was just seen on another
// interface (e.g. a bridge and its member port), so it isn't counted twice.
func (s *pcapSource) duplicate(ev *PacketEvent) bool {
	if ev.Sig == 0 {
		return false
	}
	now := time.Now()
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	if p, ok := s.seen[ev.Sig]; ok && p.iface != ev.Iface && now.Sub(p.at) < 100*time.Millisecond {
		return true
	}
	if len(s.seen) > 8192 {
		for k, p := range s.seen {
			if now.Sub(p.at) > 100*time.Millisecond {
				delete(s.seen, k)
			}
		}
	}
	s.seen[ev.Sig] = seenPkt{at: now, iface: ev.Iface}
	return false
}

func (s *pcapSource) sendErr(err error) {
	select {
	case s.errs <- err:
	default:
	}
}

func (s *pcapSource) Update(specs []TargetSpec) {
	f := BuildBPF(specs)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filter = f
	for _, r := range s.readers {
		select { // latest filter wins
		case <-r.filter:
		default:
		}
		r.filter <- f
	}
}

func (s *pcapSource) Events() <-chan *PacketEvent { return s.events }
func (s *pcapSource) Errors() <-chan error        { return s.errs }
func (s *pcapSource) Dropped() uint64             { return s.dropped.Load() }

func (s *pcapSource) Describe() string {
	names := s.Interfaces()
	if len(names) > 3 {
		return fmt.Sprintf("%d interfaces", len(names))
	}
	return strings.Join(names, ",")
}

func (s *pcapSource) Close() {
	s.once.Do(func() { close(s.done) })
}

// ---- interface discovery ----------------------------------------------------

// DeviceInfo describes a capturable network interface.
type DeviceInfo struct {
	Name     string
	Kind     string // friendly description: Wi-Fi, loopback, VPN/tunnel…
	Addrs    []string
	Up       bool
	Loopback bool
	Default  bool // carries the default route
}

// Active reports whether the interface carries real traffic: it is up and is
// loopback or has an address that isn't link-local (fe80::/169.254). Idle
// tunnels and AirDrop interfaces only have link-local addresses.
func (d DeviceInfo) Active() bool {
	if !d.Up {
		return false
	}
	for _, a := range d.Addrs {
		ip := net.ParseIP(a)
		if ip != nil && (d.Loopback || !(ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())) {
			return true
		}
	}
	return false
}

func ListDevices() ([]DeviceInfo, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	def, _ := defaultInterface()
	ports := hardwarePorts()
	var out []DeviceInfo
	for _, d := range devs {
		di := DeviceInfo{Name: d.Name, Up: d.Flags&0x2 != 0, Loopback: d.Flags&0x1 != 0, Default: d.Name == def}
		for _, a := range d.Addresses {
			di.Addrs = append(di.Addrs, a.IP.String())
		}
		di.Kind = ports[d.Name]
		if di.Kind == "" {
			di.Kind = d.Description
		}
		if di.Kind == "" {
			di.Kind = guessKind(d.Name, di.Loopback)
		}
		out = append(out, di)
	}
	// default first, then active, then by name
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Default != b.Default {
			return a.Default
		}
		if a.Active() != b.Active() {
			return a.Active()
		}
		return a.Name < b.Name
	})
	return out, nil
}

func guessKind(name string, loopback bool) string {
	if loopback {
		return "loopback"
	}
	prefixes := []struct{ p, k string }{
		{"utun", "VPN / tunnel"}, {"tun", "VPN / tunnel"}, {"tap", "VPN / tunnel"}, {"wg", "WireGuard"},
		{"ipsec", "VPN / tunnel"}, {"gif", "tunnel"}, {"stf", "6to4 tunnel"}, {"awdl", "AirDrop (AWDL)"},
		{"llw", "low-latency WLAN"}, {"bridge", "bridge"}, {"br-", "bridge"}, {"docker", "Docker"},
		{"veth", "container veth"}, {"vmnet", "virtual machine"}, {"vnic", "virtual machine"},
		{"ap", "access point"}, {"anpi", "internal (Apple)"}, {"en", "Ethernet / Wi-Fi"},
		{"eth", "Ethernet"}, {"wl", "Wi-Fi"}, {"pktap", "packet tap"}, {"any", "all (pseudo)"},
	}
	for _, x := range prefixes {
		if strings.HasPrefix(name, x.p) {
			return x.k
		}
	}
	return ""
}

var (
	hwPortsOnce sync.Once
	hwPorts     map[string]string
)

// hardwarePorts maps macOS device names to their friendly names ("en0" → "Wi-Fi").
func hardwarePorts() map[string]string {
	hwPortsOnce.Do(func() {
		hwPorts = map[string]string{}
		if runtime.GOOS != "darwin" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "networksetup", "-listallhardwareports").Output()
		if err != nil {
			return
		}
		port := ""
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(l, "Hardware Port: "); ok {
				port = v
			} else if v, ok := strings.CutPrefix(l, "Device: "); ok && port != "" {
				hwPorts[strings.TrimSpace(v)] = port
			}
		}
	})
	return hwPorts
}

// defaultInterface picks the interface that owns the default route's source
// address (found by "connecting" a UDP socket — no packets are sent).
func defaultInterface() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	if c, err := net.Dial("udp", "8.8.8.8:53"); err == nil {
		local := c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
		for _, d := range devs {
			for _, a := range d.Addresses {
				if a.IP.Equal(local) {
					return d.Name, nil
				}
			}
		}
	}
	for _, d := range devs {
		if d.Flags&0x1 != 0 { // PCAP_IF_LOOPBACK
			continue
		}
		for _, a := range d.Addresses {
			if a.IP.To4() != nil {
				return d.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no usable network interface found; pick one with -i (see -list)")
}

func listInterfaces() error {
	devs, err := ListDevices()
	if err != nil {
		return err
	}
	for _, d := range devs {
		mark := "  "
		if d.Default {
			mark = "* "
		} else if d.Active() {
			mark = "+ "
		}
		fmt.Printf("%s%-10s %-20s %s\n", mark, d.Name, d.Kind, strings.Join(d.Addrs, ", "))
	}
	fmt.Println("\n* = default   + = included by -i all (up, with a non-link-local address)")
	return nil
}

var localIPs = func() map[string]bool {
	m := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			m[n.IP.String()] = true
		}
	}
	return m
}()
