package main

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func TestParseTargets(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1:443":              "1.1.1.1:443",
		"8.8.8.8:53 udp":           "8.8.8.8:53 udp",
		"10.0.0.5:22,80,8000-8100": "10.0.0.5:22,80,8000-8100",
		"192.168.1.0/24":           "192.168.1.0/24",
		"10.0.0.0/24:80":           "10.0.0.0/24:80",
		"[2001:db8::1]:443 tcp":    "[2001:db8::1]:443 tcp",
		"2001:db8::1":              "2001:db8::1",
		"1.1.1.1:https":            "1.1.1.1:443",
		"9.9.9.9 icmp":             "9.9.9.9 icmp",
	}
	for in, want := range cases {
		s, err := ParseTargetLine(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := s.String(); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
		if _, err := ParseTargetLine(s.String()); err != nil {
			t.Errorf("round trip %q: %v", s.String(), err)
		}
	}
	for _, bad := range []string{"1.1.1.1:70000", "1.1.1.1 icmp:22", "1.2.3.4:22 icmp", "1.2.3.4 sctp", "10.0.0.0/99"} {
		if _, err := ParseTargetLine(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestBPFCompiles(t *testing.T) {
	var specs []TargetSpec
	for _, l := range []string{"1.1.1.1:443", "8.8.8.8:53 udp", "10.0.0.0/24:22,8000-8100", "[2001:db8::1]:443 tcp", "9.9.9.9 icmp", "4.4.4.4"} {
		s, _ := ParseTargetLine(l)
		specs = append(specs, s)
	}
	f := BuildBPF(specs)
	t.Log(f)
	for _, filter := range []string{f, BuildBPF(nil)} {
		if _, err := compileBPF(filter); err != nil {
			t.Fatalf("filter %q: %v", filter, err)
		}
	}
}

func TestSNI(t *testing.T) {
	app, info := sniffTCP(fakeClientHello("api.example.org"), 50000, 443)
	if app != "TLS" || info != "TLS ClientHello SNI=api.example.org" {
		t.Fatalf("got %q %q", app, info)
	}
}

// Drives a full TCP lifecycle through serialise → decode → tracker.
func TestTCPStateMachine(t *testing.T) {
	spec, _ := ParseTargetLine("1.1.1.1:443")
	tg := NewTarget(1, spec)
	cli, srv := net.ParseIP("192.168.1.42").To4(), net.ParseIP("1.1.1.1").To4()
	s := &demoSource{events: make(chan *PacketEvent, 100), done: make(chan struct{}), peer4: cli}
	c := &tcpSim{s: s, cIP: cli, sIP: srv, cPort: 50000, sPort: 443, cSeq: 1000, sSeq: 9000, cWin: 65535, sWin: 65535}
	feed := func() *LoggedPacket {
		ev := <-s.events
		toT, ok := spec.Match(ev)
		if !ok {
			t.Fatalf("packet did not match target")
		}
		tg.Ingest(ev, toT, time.Now())
		return tg.Log[len(tg.Log)-1]
	}
	conn := func() *Conn {
		for _, c := range tg.Conns {
			return c
		}
		return nil
	}
	steps := []struct {
		client bool
		f      TCPFlags
		data   []byte
		state  ConnState
		kind   Kind
	}{
		{true, FlagSYN, nil, StSynSent, KSyn},
		{false, FlagSYN | FlagACK, nil, StSynRcvd, KSynAck},
		{true, FlagACK, nil, StEstablished, KAck},
		{true, FlagPSH | FlagACK, fakeClientHello("x.com"), StEstablished, KData},
		{false, FlagACK, nil, StEstablished, KAck},
		{true, FlagFIN | FlagACK, nil, StFinWait, KFin},
		{false, FlagFIN | FlagACK, nil, StClosing, KFin},
		{true, FlagACK, nil, StClosed, KAck},
	}
	for i, st := range steps {
		c.send(st.client, st.f, st.data)
		lp := feed()
		if conn().State != st.state || lp.Kind != st.kind {
			t.Fatalf("step %d (%s): state %s kind %d, want %s %d — %s", i, st.f, conn().State, lp.Kind, st.state, st.kind, lp.Explain)
		}
	}
	if conn().Stages != stgSYN|stgSYNACK|stgACK|stgDATA|stgFIN|stgCLOSED {
		t.Fatalf("stages %b", conn().Stages)
	}
	if tg.Log[3].ToTarget != true || tg.Log[1].ToTarget != false {
		t.Fatal("direction wrong")
	}
	if !strings.Contains(tg.Log[3].Info, "SNI=x.com") || tg.Log[3].RelSeq != 1 {
		t.Fatalf("data packet info %q relseq %d", tg.Log[3].Info, tg.Log[3].RelSeq)
	}
	// retransmission detection
	seq := c.cSeq
	c.sendAt(true, FlagPSH|FlagACK, []byte("again"), seq-10)
	if lp := feed(); !lp.Retrans {
		t.Fatalf("expected retransmission, got %s", lp.Explain)
	}
	// refused connection
	tg3 := NewTarget(3, spec)
	tg = tg3
	c2 := &tcpSim{s: s, cIP: cli, sIP: srv, cPort: 50001, sPort: 443, cSeq: 5, sSeq: 0}
	c2.send(true, FlagSYN, nil)
	feed()
	c2.sendAt(false, FlagRST|FlagACK, nil, 0)
	feed()
	if conn().State != StRefused {
		t.Fatalf("want REFUSED got %s", conn().State)
	}
	lines := inspectLines(tg.Log[0])
	if !strings.Contains(strings.Join(lines, "\n"), "MSS=1460") {
		t.Fatalf("inspector missing TCP options:\n%s", strings.Join(lines, "\n"))
	}
}

// Renders the real UI fed by demo traffic. Set PKTTRACK_SNAPSHOT=1 to print it.
func TestRenderWithDemo(t *testing.T) {
	src := NewDemoSource()
	defer src.Close()
	var specs []TargetSpec
	for _, l := range []string{"1.1.1.1:443", "8.8.8.8:53 udp", "192.168.1.1 icmp", "10.0.0.0/24:22,80"} {
		s, _ := ParseTargetLine(l)
		specs = append(specs, s)
	}
	m := newModel(src, specs, "", "")
	m.Update(tea.WindowSizeMsg{Width: 150, Height: 46})
	busiest := func() int {
		b := 0
		for i, t := range m.targets {
			if len(t.Log) > len(m.targets[b].Log) {
				b = i
			}
		}
		return b
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(m.targets[busiest()].Log) < 12 {
		time.Sleep(50 * time.Millisecond)
		m.Update(tickMsg(time.Now()))
	}
	m.sel = busiest()
	for i := 0; i < 4; i++ { // let the animation be mid-flight
		time.Sleep(20 * time.Millisecond)
		m.Update(tickMsg(time.Now()))
	}
	if len(m.targets[m.sel].Log) == 0 {
		t.Fatal("demo produced no packets")
	}
	views := []string{m.View()}
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	views = append(views, m.View())
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("v")})
	views = append(views, m.View())
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	for _, r := range "9.9.9.9:53 udp" {
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	views = append(views, m.View())
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if len(m.targets) != 5 || m.targets[4].Spec.String() != "9.9.9.9:53 udp" {
		t.Fatalf("form did not add target: %d %v", len(m.targets), m.form)
	}
	for i, v := range views {
		lines := strings.Split(v, "\n")
		if len(lines) != 46 {
			t.Errorf("view %d has %d lines, want 46", i, len(lines))
		}
		for j, l := range lines {
			if w := ansi.StringWidth(l); w > 150 {
				t.Errorf("view %d line %d is %d wide", i, j, w)
			}
		}
		if os.Getenv("PKTTRACK_SNAPSHOT") != "" {
			t.Logf("\n%s", ansi.Strip(v))
		}
	}
}

func compileBPF(expr string) ([]pcap.BPFInstruction, error) {
	return pcap.CompileBPFFilter(layers.LinkTypeEthernet, 2048, expr)
}
