package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// injector is implemented by sources that fake probes (demo mode).
type injector interface {
	Inject(req ProbeReq, seq int) ProbeResult
}

type probeMsg struct {
	gen, seq, tid int
	req           ProbeReq
	res           ProbeResult
}

// probeState tracks the probe run in progress (one at a time).
type probeState struct {
	gen     int
	running bool
	req     ProbeReq
	tid     int
	done    int
	ok      int
	peers   map[string]bool  // our local ip:port of probe connections, for tagging
	last    map[int]ProbeReq // last request per target ID, for quick re-send
	warn    string
}

const (
	pfAddr = iota
	pfPort
	pfMethod
	pfCount
	pfPayload
	pfFields
)

type probeForm struct {
	addr, port, count, payload textinput.Model
	proto                      Proto // ProtoAny = auto
	focus                      int
	host                       string
	err                        string
}

func newProbeForm(t *Target, last *ProbeReq) *probeForm {
	r := defaultProbe(&t.Spec)
	auto := true
	if last != nil {
		r, auto = *last, false
	}
	mk := func(ph string, w int) textinput.Model {
		ti := textinput.New()
		ti.Placeholder, ti.CharLimit, ti.Width, ti.Prompt = ph, 512, w, ""
		return ti
	}
	f := &probeForm{host: r.Host}
	f.addr = mk("IP or hostname to send to", 42)
	f.port = mk("e.g. 443  (blank for ping)", 42)
	f.count = mk("1", 6)
	f.payload = mk(`blank = smart default · e.g. hello\n`, 42)
	if r.IP != nil {
		f.addr.SetValue(r.IP.String())
	}
	if r.Port != 0 {
		f.port.SetValue(strconv.Itoa(int(r.Port)))
	}
	f.count.SetValue(strconv.Itoa(max(1, r.Count)))
	f.payload.SetValue(strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(r.Payload))
	if !auto {
		f.proto = r.Proto
	} else if t.Spec.Proto != ProtoAny {
		f.proto = t.Spec.Proto
	}
	f.addr.Focus()
	return f
}

func (f *probeForm) input(i int) *textinput.Model {
	switch i {
	case pfAddr:
		return &f.addr
	case pfPort:
		return &f.port
	case pfCount:
		return &f.count
	case pfPayload:
		return &f.payload
	}
	return nil
}

func (f *probeForm) setFocus(i int) {
	f.focus = (i + pfFields) % pfFields
	for j := 0; j < pfFields; j++ {
		if in := f.input(j); in != nil {
			in.Blur()
		}
	}
	if in := f.input(f.focus); in != nil {
		in.Focus()
	}
}

func (f *probeForm) updateInputs(msg tea.Msg) tea.Cmd {
	var cmds []tea.Cmd
	for j := 0; j < pfFields; j++ {
		if in := f.input(j); in != nil {
			var c tea.Cmd
			*in, c = in.Update(msg)
			cmds = append(cmds, c)
		}
	}
	return tea.Batch(cmds...)
}

func (m *model) openProbeForm() tea.Cmd {
	t := m.current()
	if t == nil {
		m.setStatus("add a target first (press a)", true)
		return nil
	}
	var last *ProbeReq
	if r, ok := m.probe.last[t.ID]; ok {
		last = &r
	}
	m.probeForm = newProbeForm(t, last)
	return textinput.Blink
}

func (m *model) updateProbeForm(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.probeForm
	switch k.String() {
	case "esc":
		m.probeForm = nil
		return m, nil
	case "tab", "down":
		f.setFocus(f.focus + 1)
		return m, nil
	case "shift+tab", "up":
		f.setFocus(f.focus - 1)
		return m, nil
	case "enter":
		req, warn, err := f.build(m.current())
		if err != nil {
			f.err = err.Error()
			return m, nil
		}
		m.probeForm = nil
		return m, m.startProbe(m.current(), req, warn)
	}
	if f.focus == pfMethod {
		switch k.String() {
		case "left", "h":
			f.proto = (f.proto + 3) % 4
		case "right", "l", " ":
			f.proto = (f.proto + 1) % 4
		}
		return m, nil
	}
	f.err = ""
	return m, f.updateInputs(k)
}

// build validates the form into a probe request. warn is non-empty when the
// probe is valid but its packets won't be counted under the selected target.
func (f *probeForm) build(t *Target) (req ProbeReq, warn string, err error) {
	addr := strings.TrimSpace(f.addr.Value())
	portS := strings.TrimSpace(f.port.Value())
	if portS == "" { // allow "1.2.3.4:443" in the address field
		addr, portS = SplitHostPorts(addr)
	}
	addr = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	if addr == "" {
		return req, "", fmt.Errorf("enter an IP address or hostname to send to")
	}
	req.Host = f.host
	if ip := net.ParseIP(addr); ip != nil {
		req.IP = ip
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ips, lerr := net.DefaultResolver.LookupIP(ctx, "ip", addr)
		if lerr != nil || len(ips) == 0 {
			return req, "", fmt.Errorf("cannot resolve %q", addr)
		}
		req.IP, req.Host = ips[0], addr
		for _, ip := range ips {
			if ip.To4() != nil {
				req.IP = ip
				break
			}
		}
	}
	if v4 := req.IP.To4(); v4 != nil {
		req.IP = v4
	}
	if portS != "" {
		p, perr := parsePort(portS)
		if perr != nil {
			return req, "", perr
		}
		req.Port = p
	}
	req.Proto = resolveProbeProto(f.proto, req.Port)
	if req.Proto != ProtoICMP && req.Port == 0 {
		return req, "", fmt.Errorf("%s needs a port (or choose icmp to ping)", req.Proto)
	}
	if req.Proto == ProtoICMP {
		req.Port = 0
	}
	n, cerr := strconv.Atoi(strings.TrimSpace(f.count.Value()))
	if strings.TrimSpace(f.count.Value()) == "" {
		n, cerr = 1, nil
	}
	if cerr != nil || n < 1 || n > 1000 {
		return req, "", fmt.Errorf("count must be 1–1000")
	}
	req.Count = n
	req.Payload = strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t").Replace(f.payload.Value())
	if req.Payload != "" && req.Proto == ProtoICMP {
		return req, "", fmt.Errorf("custom payloads are for tcp/udp only")
	}
	req.Timeout = 3 * time.Second

	if t != nil {
		s := &t.Spec
		switch {
		case !s.MatchIP(req.IP):
			warn = req.IP.String() + " is outside target " + s.Label()
		case req.Proto != ProtoICMP && !s.MatchPort(req.Port):
			warn = fmt.Sprintf("port %d isn't one of %s's ports", req.Port, s.Label())
		case s.Proto != ProtoAny && s.Proto != req.Proto:
			warn = fmt.Sprintf("target only tracks %s", s.Proto)
		}
		if warn != "" {
			warn += " — its packets won't show in this target"
		}
	}
	return req, warn, nil
}

func (m *model) startProbe(t *Target, req ProbeReq, warn string) tea.Cmd {
	if t == nil {
		return nil
	}
	p := &m.probe
	p.gen++
	p.running, p.req, p.tid, p.done, p.ok, p.warn = true, req, t.ID, 0, 0, warn
	p.last[t.ID] = req
	t.ProbeLast, t.ProbeOK = "sending "+req.String()+"…", true
	if warn != "" {
		m.setStatus("probe: "+warn, true)
	}
	return m.probeStep(1, 0)
}

func (m *model) probeStep(seq int, delay time.Duration) tea.Cmd {
	gen, req, tid := m.probe.gen, m.probe.req, m.probe.tid
	inj, _ := m.src.(injector)
	return func() tea.Msg {
		if delay > 0 {
			time.Sleep(delay)
		}
		var res ProbeResult
		if inj != nil {
			res = inj.Inject(req, seq)
		} else {
			res = RunProbe(req, seq)
		}
		return probeMsg{gen: gen, seq: seq, tid: tid, req: req, res: res}
	}
}

func (m *model) stopProbe() {
	if m.probe.running {
		m.probe.gen++ // in-flight results become stale
		m.probe.running = false
		m.setStatus(fmt.Sprintf("probe stopped after %d of %d", m.probe.done, m.probe.req.Count), false)
	}
}

func (m *model) handleProbeMsg(msg probeMsg) tea.Cmd {
	p := &m.probe
	if msg.gen != p.gen {
		return nil
	}
	p.done++
	if msg.res.OK {
		p.ok++
	}
	if msg.res.LocalAddr != "" {
		if len(p.peers) > 2000 {
			p.peers = map[string]bool{}
		}
		p.peers[msg.res.LocalAddr] = true
	}
	var t *Target
	for _, x := range m.targets {
		if x.ID == msg.tid {
			t = x
		}
	}
	line := fmt.Sprintf("#%d/%d %s → %s", msg.seq, msg.req.Count, msg.req, msg.res.Summary)
	if t != nil {
		t.ProbeLast, t.ProbeOK, t.ProbeAt = line, msg.res.OK, time.Now()
	}
	if msg.seq < msg.req.Count {
		if p.warn == "" {
			m.setStatus("probe "+line, !msg.res.OK)
		}
		return m.probeStep(msg.seq+1, time.Second)
	}
	p.running = false
	switch {
	case msg.req.Count > 1:
		m.setStatus(fmt.Sprintf("probe finished: %d/%d succeeded · last: %s", p.ok, msg.req.Count, msg.res.Summary), p.ok == 0)
	case p.warn == "":
		m.setStatus("probe "+line, !msg.res.OK)
	}
	return nil
}

func (m *model) probeLine(t *Target, iw int) string {
	if t.ProbeLast == "" {
		return " " + dim("probe ▸ press ") + keyHint("t", "") + dim("to send test packets to this target (") + keyHint("T", "") + dim("re-sends)")
	}
	icon := fg(colOK).Bold(true).Render("✔")
	if !t.ProbeOK {
		icon = fg(colErr).Bold(true).Render("✖")
	}
	head := dim("probe ▸ ")
	if m.probe.running && m.probe.tid == t.ID {
		spin := []string{"◐", "◓", "◑", "◒"}[time.Now().UnixMilli()/150%4]
		head = fg(colWarn).Bold(true).Render(spin+" probing ") + dim("(s stops) ")
	}
	return fit(" "+head+icon+" "+t.ProbeLast, iw)
}

func (f *probeForm) view(w, h int, t *Target) string {
	acc := fg(colFocus).Bold(true)
	label := func(i int, s string) string {
		if f.focus == i {
			return acc.Render("▸ " + s)
		}
		return "  " + s
	}
	field := func(i int, ti textinput.Model, width int) string {
		b := fg(colBorder)
		if f.focus == i {
			b = fg(colFocus)
		}
		return b.Render("[ ") + fit(ti.View(), width) + b.Render(" ]")
	}
	var methods []string
	for p := ProtoAny; p <= ProtoICMP; p++ {
		name := p.String()
		if p == ProtoAny {
			name = "auto"
		}
		if p == f.proto {
			methods = append(methods, acc.Reverse(f.focus == pfMethod).Render(" "+name+" "))
		} else {
			methods = append(methods, dim(" "+name+" "))
		}
	}
	ind := "                "
	what := map[Proto]string{
		ProtoAny:  "auto: no port → ping · 53/123 → udp · otherwise tcp",
		ProtoTCP:  "tcp: real handshake; TLS on 443-type ports, HTTP HEAD on 80-type ports",
		ProtoUDP:  "udp: datagram (DNS query on 53, NTP on 123) and wait for a reply",
		ProtoICMP: "icmp: echo request (ping); no port",
	}[f.proto]
	lines := []string{
		dim("  Sends real traffic from this machine; watch it appear in the flow & packet list."),
		"",
		label(pfAddr, "Address     ") + field(pfAddr, f.addr, 43),
		dim(ind + "any IP or hostname — prefilled from " + t.Spec.Label()),
		label(pfPort, "Port        ") + field(pfPort, f.port, 43),
		"",
		label(pfMethod, "Method      ") + "  " + strings.Join(methods, " "),
		dim(ind + what),
		"",
		label(pfCount, "Count       ") + field(pfCount, f.count, 7) + dim("  one probe per second"),
		label(pfPayload, "Payload     ") + field(pfPayload, f.payload, 43),
		dim(ind + `optional text to send over tcp/udp; \n \r \t allowed`),
		"",
	}
	if f.err != "" {
		lines = append(lines, fg(colErr).Render("  ✖ "+f.err))
	} else {
		lines = append(lines, "")
	}
	lines = append(lines, "", "  "+keyHint("enter", "send")+"  "+keyHint("tab", "next field")+"  "+keyHint("←/→", "method")+"  "+keyHint("esc", "cancel"))
	bw := min(w, 92)
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, box("Send test packets · "+t.Spec.Label(), lines, bw, len(lines)+2, true))
}
