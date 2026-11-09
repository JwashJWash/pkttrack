package main

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestProbeLocal(t *testing.T) {
	// TCP echo server to exercise connect + custom payload.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 100)
			n, _ := c.Read(buf)
			c.Write(append([]byte("echo: "), buf[:n]...))
			c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	lo := net.ParseIP("127.0.0.1").To4()

	r := RunProbe(ProbeReq{IP: lo, Port: port, Proto: ProtoTCP, Payload: "hi\n", Timeout: time.Second}, 1)
	if !r.OK || !strings.Contains(r.Summary, "echo: hi") || r.LocalAddr == "" {
		t.Fatalf("tcp payload probe: %+v", r)
	}
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := uint16(ln2.Addr().(*net.TCPAddr).Port)
	ln2.Close()
	r = RunProbe(ProbeReq{IP: lo, Port: closed, Proto: ProtoTCP, Timeout: time.Second}, 1)
	if r.OK || !strings.Contains(r.Summary, "refused") {
		t.Fatalf("closed tcp port: %+v", r)
	}
	u, _ := net.ListenPacket("udp", "127.0.0.1:0")
	uport := uint16(u.LocalAddr().(*net.UDPAddr).Port)
	u.Close()
	r = RunProbe(ProbeReq{IP: lo, Port: uport, Proto: ProtoUDP, Timeout: time.Second}, 1)
	if r.OK || !strings.Contains(r.Summary, "unreachable") {
		t.Fatalf("closed udp port: %+v", r)
	}
	r = RunProbe(ProbeReq{IP: lo, Proto: ProtoICMP, Timeout: time.Second}, 1)
	if !r.OK {
		t.Fatalf("ping localhost: %+v", r)
	}
	t.Logf("local ping: %s", r.Summary)
}

// Real internet probes; skipped when offline.
func TestProbeInternet(t *testing.T) {
	if c, err := net.DialTimeout("tcp", "1.1.1.1:443", 2*time.Second); err != nil {
		t.Skip("no internet:", err)
	} else {
		c.Close()
	}
	for _, r := range []ProbeReq{
		{IP: net.ParseIP("1.1.1.1").To4(), Port: 443, Proto: ProtoTCP, Host: "one.one.one.one"},
		{IP: net.ParseIP("1.1.1.1").To4(), Port: 80, Proto: ProtoTCP},
		{IP: net.ParseIP("8.8.8.8").To4(), Port: 53, Proto: ProtoUDP, Host: "github.com"},
		{IP: net.ParseIP("8.8.8.8").To4(), Proto: ProtoICMP},
	} {
		res := RunProbe(r, 1)
		t.Logf("%-20s ok=%v  %s", r.String(), res.OK, res.Summary)
		if !res.OK && r.Proto != ProtoICMP {
			t.Errorf("%s failed: %s", r, res.Summary)
		}
	}
}

func TestProbeDefaults(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1:443":           "tcp 1.1.1.1:443",
		"8.8.8.8:53":            "udp 8.8.8.8:53",
		"9.9.9.9":               "icmp 9.9.9.9",
		"10.0.0.0/24:22":        "tcp 10.0.0.1:22",
		"[2001:db8::1]:80":      "tcp [2001:db8::1]:80",
		"4.4.4.4:5000-5010 udp": "udp 4.4.4.4:5000",
	}
	for in, want := range cases {
		s, _ := ParseTargetLine(in)
		if got := defaultProbe(&s).String(); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

// Drives the probe dialog end to end in demo mode.
func TestProbeDialog(t *testing.T) {
	src := NewDemoSource()
	defer src.Close()
	s, _ := ParseTargetLine("10.0.0.0/24:22,80")
	m := newModel(src, []TargetSpec{s}, "", "")
	m.Update(tea.WindowSizeMsg{Width: 150, Height: 46})
	key := func(k string) {
		switch k {
		case "tab":
			m.Update(tea.KeyMsg{Type: tea.KeyTab})
		case "enter":
			m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		case "ctrl+u":
			m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
		default:
			for _, r := range k {
				m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
			}
		}
	}
	key("t")
	if m.probeForm == nil {
		t.Fatal("t did not open probe dialog")
	}
	if m.probeForm.addr.Value() != "10.0.0.1" || m.probeForm.port.Value() != "22" {
		t.Fatalf("prefill addr=%q port=%q", m.probeForm.addr.Value(), m.probeForm.port.Value())
	}
	// user picks a specific IP and port
	key("ctrl+u")
	key("10.0.0.77")
	key("tab")
	key("ctrl+u")
	key("80")
	key("tab")
	key("tab")
	key("ctrl+u")
	key("2")
	dialog := m.View()
	key("enter")
	if m.probeForm != nil {
		t.Fatalf("dialog still open: %s", m.probeForm.err)
	}
	if got := m.probe.req.String(); got != "tcp 10.0.0.77:80" || m.probe.req.Count != 2 {
		t.Fatalf("req %s count %d", got, m.probe.req.Count)
	}
	// run the commands like Bubble Tea would
	cmd := m.probeStep(1, 0)
	for cmd != nil {
		msg := cmd()
		_, cmd = m.Update(msg)
	}
	tg := m.targets[0]
	if !strings.Contains(tg.ProbeLast, "#2/2") || !tg.ProbeOK {
		t.Fatalf("probe line %q", tg.ProbeLast)
	}
	time.Sleep(400 * time.Millisecond)
	m.Update(tickMsg(time.Now()))
	found := false
	for _, lp := range tg.Log {
		if lp.Conn.Key.Target == "10.0.0.77:80" {
			found = true
		}
	}
	if !found {
		t.Fatal("simulated probe traffic to 10.0.0.77:80 not tracked")
	}
	main := m.View()

	// an address outside the target is allowed but warned about
	key("t")
	key("ctrl+u")
	key("192.168.5.5")
	key("enter")
	if !strings.Contains(m.status, "outside target") {
		t.Fatalf("expected outside-target warning, got %q", m.status)
	}
	// bad input stays in the dialog with an error
	key("t")
	key("tab")
	key("ctrl+u")
	key("99999")
	key("enter")
	if m.probeForm == nil || m.probeForm.err == "" {
		t.Fatal("expected validation error for port 99999")
	}
	if os.Getenv("PKTTRACK_SNAPSHOT") != "" {
		t.Logf("\n%s\n%s", ansi.Strip(dialog), ansi.Strip(main))
	}
}
