package main

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/gopacket/gopacket/layers"
)

// fakeLive is a demo source that pretends to be a switchable live capture.
type fakeLive struct {
	*demoSource
	ifaces []string
	broken map[string]bool
}

func (f *fakeLive) Interfaces() []string { return f.ifaces }
func (f *fakeLive) IfaceCount(n string) uint64 {
	if n == "en0" {
		return 1234
	}
	return 0
}
func (f *fakeLive) SetInterfaces(names []string) ([]string, map[string]error) {
	failed := map[string]error{}
	var ok []string
	for _, n := range names {
		if f.broken[n] {
			failed[n] = os.ErrPermission
		} else {
			ok = append(ok, n)
		}
	}
	sort.Strings(ok)
	f.ifaces = ok
	return ok, failed
}

func TestListDevicesAndAll(t *testing.T) {
	devs, err := ListDevices()
	if err != nil {
		t.Skip("cannot list devices:", err)
	}
	all, err := ExpandInterfaces([]string{"all"})
	if err != nil {
		t.Fatal(err)
	}
	def, _ := ExpandInterfaces(nil)
	for _, d := range devs {
		t.Logf("%-10s %-22s up=%-5v active=%-5v default=%-5v %v", d.Name, d.Kind, d.Up, d.Active(), d.Default, d.Addrs)
	}
	t.Logf("all → %v   default → %v", all, def)
	if len(def) != 1 || !devs[0].Default || devs[0].Name != def[0] {
		t.Errorf("default interface should sort first: %v / %v", def, devs[0])
	}
	if !contains(all, def[0]) {
		t.Errorf("all %v should include default %v", all, def)
	}
	got, _ := ExpandInterfaces([]string{"en0", " lo0", "en0"})
	if strings.Join(got, ",") != "en0,lo0" {
		t.Errorf("explicit list: %v", got)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestPickerMultiSelect(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "targets.txt")
	src := &fakeLive{demoSource: NewDemoSource(), ifaces: []string{"en0"}, broken: map[string]bool{"bad0": true}}
	defer src.Close()
	s, _ := ParseTargetLine("1.1.1.1:443")
	m := newModel(src, []TargetSpec{s}, cfg, "")
	m.Update(tea.WindowSizeMsg{Width: 150, Height: 46})
	press := func(keys ...string) {
		for _, k := range keys {
			switch k {
			case "enter":
				m.Update(tea.KeyMsg{Type: tea.KeyEnter})
			case "down":
				m.Update(tea.KeyMsg{Type: tea.KeyDown})
			case "space":
				m.Update(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
			default:
				m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
			}
		}
	}
	// Use a fixed device list so the test doesn't depend on this machine.
	fake := []DeviceInfo{
		{Name: "en0", Kind: "Wi-Fi", Up: true, Default: true, Addrs: []string{"192.168.1.42"}},
		{Name: "lo0", Kind: "loopback", Up: true, Loopback: true, Addrs: []string{"127.0.0.1", "::1"}},
		{Name: "utun3", Kind: "VPN / tunnel", Up: true, Addrs: []string{"10.8.0.2"}},
		{Name: "bad0", Kind: "Ethernet", Up: true, Addrs: []string{"10.9.9.9"}},
		{Name: "ap1", Kind: "access point", Up: false},
		{Name: "utun0", Kind: "VPN / tunnel", Up: true, Addrs: []string{"fe80::1"}},
	}
	open := func() {
		press("i")
		if m.picker == nil {
			t.Fatal("i did not open the picker")
		}
		m.picker.devs = fake
	}

	// multi-select: add lo0 and utun3 to en0
	open()
	if !m.picker.sel["en0"] {
		t.Fatal("current interface should be pre-selected")
	}
	press("down", "space", "down", "space")
	snap := m.View()
	press("enter")
	if m.picker != nil {
		t.Fatalf("picker still open: %s", m.picker.err)
	}
	if got := strings.Join(src.ifaces, ","); got != "en0,lo0,utun3" {
		t.Fatalf("multi-select applied %q", got)
	}
	if m.ifaceSetting != "en0,lo0,utun3" {
		t.Fatalf("setting %q", m.ifaceSetting)
	}
	if b, _ := os.ReadFile(cfg); !strings.Contains(string(b), "@interfaces en0,lo0,utun3") {
		t.Fatalf("selection not saved:\n%s", b)
	}

	// single: default only
	open()
	press("d", "enter")
	if got := strings.Join(src.ifaces, ","); got != "en0" {
		t.Fatalf("default only applied %q", got)
	}

	// all active: skips ap1 (down), reports bad0 failing, remembers "all"
	open()
	press("a", "enter")
	if got := strings.Join(src.ifaces, ","); got != "en0,lo0,utun3" {
		t.Fatalf("all applied %q", got)
	}
	if m.ifaceSetting != "all" || !strings.Contains(m.status, "could not open bad0") {
		t.Fatalf("setting %q status %q", m.ifaceSetting, m.status)
	}
	if b, _ := os.ReadFile(cfg); !strings.Contains(string(b), "@interfaces all") {
		t.Fatalf("all not saved:\n%s", b)
	}

	// A = every interface, even inactive ones
	open()
	press("A", "enter")
	if got := strings.Join(src.ifaces, ","); got != "ap1,en0,lo0,utun0,utun3" {
		t.Fatalf("every applied %q", got)
	}

	// none selected is refused
	open()
	press("n", "enter")
	if m.picker == nil || m.picker.err == "" {
		t.Fatal("empty selection should be refused")
	}
	press("q")

	// saved file still loads as targets + directive
	lines, _ := loadConfig(cfg)
	var tg []string
	for _, l := range lines {
		if !strings.HasPrefix(l, ifaceDirective) {
			tg = append(tg, l)
		}
	}
	if strings.Join(tg, ";") != "1.1.1.1:443" {
		t.Fatalf("targets after save: %v", tg)
	}

	// with several interfaces the packet list shows an IF column
	for i := 0; i < 60 && len(m.targets[0].Log) < 3; i++ {
		time.Sleep(100 * time.Millisecond)
		m.Update(tickMsg(time.Now()))
	}
	main := m.View()
	if !strings.Contains(ansi.Strip(main), " IF ") {
		t.Error("expected IF column in packet list")
	}
	if os.Getenv("PKTTRACK_SNAPSHOT") != "" {
		t.Logf("\n%s\n%s", ansi.Strip(snap), ansi.Strip(main))
	}
}

func TestPickerDemoMode(t *testing.T) {
	src := NewDemoSource()
	defer src.Close()
	m := newModel(src, nil, "", "")
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("i")})
	m.picker.devs = []DeviceInfo{{Name: "en0", Up: true, Addrs: []string{"1.2.3.4"}}}
	m.picker.sel["en0"] = true
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.picker == nil || !strings.Contains(m.picker.err, "demo") {
		t.Fatal("demo mode should explain that interface selection needs live capture")
	}
}

func TestDedupeAcrossInterfaces(t *testing.T) {
	s := &pcapSource{seen: map[uint64]seenPkt{}}
	pkt := func() []byte {
		return buildPacket(net.ParseIP("10.0.0.1").To4(), net.ParseIP("1.1.1.1").To4(), layers.IPProtocolTCP, true,
			&layers.TCP{SrcPort: 50000, DstPort: 443, SYN: true, Seq: 7})
	}
	a := decodePacket(pkt(), layers.LinkTypeEthernet, time.Now(), 0)
	b := decodePacket(pkt(), layers.LinkTypeEthernet, time.Now(), 0)
	if a.Sig == 0 {
		t.Fatal("no signature")
	}
	// buildPacket randomises the IP ID, so give b the same IP bytes as a
	b.Sig = a.Sig
	a.Iface, b.Iface = "bridge0", "en1"
	if s.duplicate(a) {
		t.Fatal("first sighting is not a duplicate")
	}
	if !s.duplicate(b) {
		t.Fatal("same packet on a second interface should be dropped")
	}
	if s.duplicate(a) {
		t.Fatal("same interface again is a genuine retransmission — keep it")
	}
	c := decodePacket(pkt(), layers.LinkTypeEthernet, time.Now(), 0)
	if c.Sig == a.Sig {
		t.Fatal("different packets (different IP ID) must not collide")
	}
}
