package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

const (
	focusTargets = iota
	focusLog
)

const (
	tickEvery  = 50 * time.Millisecond
	travelTime = 900 * time.Millisecond
	flashTime  = 250 * time.Millisecond
)

// ---- styles -----------------------------------------------------------------

var (
	colText   = lipgloss.AdaptiveColor{Light: "#1e293b", Dark: "#e2e8f0"}
	colDim    = lipgloss.AdaptiveColor{Light: "#64748b", Dark: "#64748b"}
	colBorder = lipgloss.AdaptiveColor{Light: "#cbd5e1", Dark: "#334155"}
	colFocus  = lipgloss.Color("#38bdf8")
	colOK     = lipgloss.Color("#22c55e")
	colWarn   = lipgloss.Color("#facc15")
	colErr    = lipgloss.Color("#ef4444")
	colOut    = lipgloss.Color("#38bdf8")
	colIn     = lipgloss.Color("#f472b6")

	kindColors = map[Kind]lipgloss.Color{
		KAck: "#94a3b8", KSyn: "#22c55e", KSynAck: "#2dd4bf", KData: "#60a5fa", KFin: "#facc15",
		KRst: "#ef4444", KRetrans: "#f97316", KUDP: "#c084fc", KICMP: "#fb923c", KICMPErr: "#ef4444",
	}
	stateColors = map[ConnState]lipgloss.Color{
		StNew: "#94a3b8", StSynSent: "#22c55e", StSynRcvd: "#2dd4bf", StEstablished: "#4ade80",
		StFinWait: "#facc15", StClosing: "#facc15", StClosed: "#64748b", StReset: "#ef4444",
		StRefused: "#ef4444", StActive: "#c084fc",
	}
)

func fg(c lipgloss.TerminalColor) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }
func dim(s string) string                        { return fg(colDim).Render(s) }
func bold(s string) string                       { return lipgloss.NewStyle().Bold(true).Render(s) }
func kc(k Kind) lipgloss.Style                   { return fg(kindColors[k]) }

func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	sw := ansi.StringWidth(s)
	if sw > w {
		s = ansi.Truncate(s, w, "…")
		sw = ansi.StringWidth(s)
	}
	return s + strings.Repeat(" ", w-sw)
}

func fitRight(s string, w int) string {
	sw := ansi.StringWidth(s)
	if sw > w {
		return ansi.TruncateLeft(s, sw-w+1, "…")
	}
	return strings.Repeat(" ", w-sw) + s
}

func center(s string, w int) string {
	sw := ansi.StringWidth(s)
	if sw >= w {
		return fit(s, w)
	}
	l := (w - sw) / 2
	return strings.Repeat(" ", l) + s + strings.Repeat(" ", w-sw-l)
}

// box draws a rounded frame of exactly w×h cells with a title in the top edge.
func box(title string, lines []string, w, h int, focused bool) string {
	bc := lipgloss.TerminalColor(colBorder)
	if focused {
		bc = colFocus
	}
	b := fg(bc)
	iw := w - 2
	if title != "" {
		title = ansi.Truncate(title, iw-4, "…")
	}
	tw := ansi.StringWidth(title)
	var sb strings.Builder
	if tw > 0 {
		sb.WriteString(b.Render("╭─ ") + bold(title) + b.Render(" "+strings.Repeat("─", max(0, iw-3-tw))+"╮"))
	} else {
		sb.WriteString(b.Render("╭" + strings.Repeat("─", iw) + "╮"))
	}
	for i := 0; i < h-2; i++ {
		l := ""
		if i < len(lines) {
			l = lines[i]
		}
		sb.WriteString("\n" + b.Render("│") + fit(l, iw) + b.Render("│"))
	}
	sb.WriteString("\n" + b.Render("╰"+strings.Repeat("─", iw)+"╯"))
	return sb.String()
}

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

func sparkline(vals []int, mx int, c lipgloss.TerminalColor) string {
	var sb strings.Builder
	on, off := fg(c), fg(colBorder)
	for _, v := range vals {
		if v <= 0 {
			sb.WriteString(off.Render("▁"))
			continue
		}
		i := v * (len(sparkRunes) - 1) / max(mx, 1)
		sb.WriteString(on.Render(string(sparkRunes[min(i, len(sparkRunes)-1)])))
	}
	return sb.String()
}

// ---- model ------------------------------------------------------------------

type tickMsg time.Time

type model struct {
	src     Source
	targets []*Target
	nextID  int
	sel     int
	tgtOff  int
	focus   int

	follow   bool
	frozen   bool
	explain  bool
	showHelp bool

	form      *targetForm
	inspect   *LoggedPacket
	inspLines []string
	inspOff   int

	undo    *Target
	undoIdx int

	width, height int
	status        string
	statusErr     bool
	statusAt      time.Time
	cfgPath       string
	ignored       uint64

	probe     probeState
	probeForm *probeForm

	picker       *ifacePicker
	ifaceSetting string // remembered interface choice: "", "all" or "en0,lo0"
}

func newModel(src Source, specs []TargetSpec, cfgPath, notice string) *model {
	m := &model{src: src, follow: true, cfgPath: cfgPath,
		probe: probeState{peers: map[string]bool{}, last: map[int]ProbeReq{}}}
	for _, s := range specs {
		m.addTarget(s)
	}
	m.src.Update(m.activeSpecs())
	if notice != "" {
		m.setStatus(notice, strings.HasPrefix(notice, "warning"))
	}
	return m
}

func (m *model) addTarget(s TargetSpec) {
	m.nextID++
	m.targets = append(m.targets, NewTarget(m.nextID, s))
}

func (m *model) current() *Target {
	if m.sel >= 0 && m.sel < len(m.targets) {
		return m.targets[m.sel]
	}
	return nil
}

func (m *model) activeSpecs() []TargetSpec {
	var out []TargetSpec
	for _, t := range m.targets {
		if !t.Paused {
			out = append(out, t.Spec)
		}
	}
	return out
}

func (m *model) applyTargets() {
	m.src.Update(m.activeSpecs())
	if m.cfgPath == "" {
		return
	}
	all := make([]TargetSpec, len(m.targets))
	for i, t := range m.targets {
		all[i] = t.Spec
	}
	if err := saveConfig(m.cfgPath, all, m.ifaceSetting); err != nil {
		m.setStatus("could not save targets: "+err.Error(), true)
	}
}

func (m *model) setStatus(s string, isErr bool) {
	m.status, m.statusErr, m.statusAt = s, isErr, time.Now()
}

func tick() tea.Cmd {
	return tea.Tick(tickEvery, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *model) Init() tea.Cmd { return tick() }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tickMsg:
		m.drain()
		return m, tick()
	case probeMsg:
		return m, m.handleProbeMsg(msg)
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.probeForm != nil {
			return m.updateProbeForm(msg)
		}
		if m.picker != nil {
			return m.updatePicker(msg)
		}
		if m.form != nil {
			return m.updateForm(msg)
		}
		if m.showHelp {
			m.showHelp = false
			return m, nil
		}
		if m.inspect != nil {
			return m.updateInspector(msg)
		}
		return m.updateMain(msg)
	}
	if m.form != nil { // cursor blink etc.
		return m, m.form.updateInputs(msg)
	}
	if m.probeForm != nil {
		return m, m.probeForm.updateInputs(msg)
	}
	return m, nil
}

func (m *model) drain() {
	now := time.Now()
loop:
	for i := 0; i < 20000; i++ {
		select {
		case ev := <-m.src.Events():
			if m.frozen {
				m.ignored++
				continue
			}
			for _, t := range m.targets {
				if t.Paused {
					continue
				}
				if toT, ok := t.Spec.Match(ev); ok {
					t.Ingest(ev, toT, now)
				}
			}
		default:
			break loop
		}
	}
errs:
	for {
		select {
		case err := <-m.src.Errors():
			m.setStatus(err.Error(), true)
		default:
			break errs
		}
	}
	for _, t := range m.targets {
		t.prune(now)
	}
	if m.status != "" {
		ttl := 6 * time.Second
		if m.statusErr {
			ttl = 15 * time.Second
		}
		if now.Sub(m.statusAt) > ttl {
			m.status = ""
		}
	}
}

func (m *model) updateMain(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	t := m.current()
	switch k.String() {
	case "q":
		return m, tea.Quit
	case "t":
		return m, m.openProbeForm()
	case "i", "I":
		m.openIfacePicker()
	case "T":
		if t != nil {
			req, ok := m.probe.last[t.ID]
			if !ok {
				req = defaultProbe(&t.Spec)
			}
			if req.IP == nil {
				return m, m.openProbeForm()
			}
			return m, m.startProbe(t, req, "")
		}
	case "s":
		m.stopProbe()
	case "?":
		m.showHelp = true
	case "a", "+", "n":
		m.form = newForm(nil, -1)
		return m, textinput.Blink
	case "e":
		if t != nil {
			m.form = newForm(&t.Spec, m.sel)
			return m, textinput.Blink
		}
	case "d", "x", "delete":
		if t != nil {
			m.undo, m.undoIdx = t, m.sel
			m.targets = append(m.targets[:m.sel], m.targets[m.sel+1:]...)
			if m.sel >= len(m.targets) && m.sel > 0 {
				m.sel--
			}
			m.applyTargets()
			m.setStatus("Removed "+t.Spec.String()+" — press u to undo", false)
		}
	case "u":
		if m.undo != nil {
			i := min(m.undoIdx, len(m.targets))
			m.targets = append(m.targets[:i], append([]*Target{m.undo}, m.targets[i:]...)...)
			m.sel = i
			m.setStatus("Restored "+m.undo.Spec.String(), false)
			m.undo = nil
			m.applyTargets()
		}
	case " ":
		if t != nil {
			t.Paused = !t.Paused
			m.applyTargets()
			if t.Paused {
				m.setStatus("Paused "+t.Spec.String(), false)
			} else {
				m.setStatus("Resumed "+t.Spec.String(), false)
			}
		}
	case "c":
		if t != nil {
			nt := NewTarget(t.ID, t.Spec)
			nt.Paused = t.Paused
			m.targets[m.sel] = nt
			m.setStatus("Cleared stats for "+t.Spec.String(), false)
		}
	case "p":
		m.frozen = !m.frozen
	case "v":
		m.explain = !m.explain
	case "f":
		m.follow = !m.follow
	case "tab", "shift+tab":
		m.focus = 1 - m.focus
	case "esc":
		m.focus = focusTargets
	case "up", "k":
		if m.focus == focusTargets {
			m.sel = max(0, m.sel-1)
		} else {
			m.moveLog(-1)
		}
	case "down", "j":
		if m.focus == focusTargets {
			m.sel = min(len(m.targets)-1, m.sel+1)
			m.sel = max(m.sel, 0)
		} else {
			m.moveLog(1)
		}
	case "pgup":
		m.moveLog(-15)
	case "pgdown":
		m.moveLog(15)
	case "home", "g":
		if t != nil {
			m.follow = false
			t.logCursor = 0
		}
	case "end", "G":
		m.follow = true
	case "enter":
		if m.focus == focusTargets {
			m.focus = focusLog
		} else if t != nil && len(t.Log) > 0 {
			if m.follow {
				t.logCursor = len(t.Log) - 1
			}
			m.follow = false
			m.openInspector(t.Log[t.logCursor])
		}
	default:
		if s := k.String(); len(s) == 1 && s[0] >= '1' && s[0] <= '9' {
			if i := int(s[0] - '1'); i < len(m.targets) {
				m.sel = i
			}
		}
	}
	return m, nil
}

func (m *model) moveLog(d int) {
	t := m.current()
	if t == nil || len(t.Log) == 0 {
		return
	}
	if m.follow {
		t.logCursor = len(t.Log) - 1
	}
	m.follow = false
	t.logCursor = max(0, min(len(t.Log)-1, t.logCursor+d))
	if d > 0 && t.logCursor == len(t.Log)-1 {
		m.follow = true
	}
}

func (m *model) openInspector(lp *LoggedPacket) {
	m.inspect, m.inspLines, m.inspOff = lp, inspectLines(lp), 0
}

func (m *model) updateInspector(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	t := m.current()
	switch k.String() {
	case "esc", "enter", "q", "backspace":
		m.inspect = nil
	case "up", "k":
		m.inspOff = max(0, m.inspOff-1)
	case "down", "j":
		m.inspOff = min(max(0, len(m.inspLines)-3), m.inspOff+1)
	case "pgup":
		m.inspOff = max(0, m.inspOff-10)
	case "pgdown":
		m.inspOff = min(max(0, len(m.inspLines)-3), m.inspOff+10)
	case "left", "h", "[":
		if t != nil && t.logCursor > 0 {
			t.logCursor--
			m.openInspector(t.Log[t.logCursor])
		}
	case "right", "l", "]":
		if t != nil && t.logCursor < len(t.Log)-1 {
			t.logCursor++
			m.openInspector(t.Log[t.logCursor])
		}
	}
	return m, nil
}

// ---- add / edit form ----------------------------------------------------------

type targetForm struct {
	host, ports textinput.Model
	proto       Proto
	focus       int
	editIdx     int
	err         string
}

func newForm(spec *TargetSpec, idx int) *targetForm {
	f := &targetForm{editIdx: idx}
	mk := func(ph string) textinput.Model {
		ti := textinput.New()
		ti.Placeholder = ph
		ti.CharLimit = 256
		ti.Width = 42
		ti.Prompt = ""
		return ti
	}
	f.host = mk("8.8.8.8 · 10.0.0.0/24 · example.com · 1.1.1.1:443")
	f.ports = mk("443 · 80,443 · 8000-8100 · https  (blank = any)")
	if spec != nil {
		f.host.SetValue(spec.Host)
		if len(spec.Ports) > 0 {
			f.ports.SetValue(spec.PortsString())
		}
		f.proto = spec.Proto
	}
	f.host.Focus()
	return f
}

func (f *targetForm) setFocus(i int) {
	f.focus = (i + 3) % 3
	f.host.Blur()
	f.ports.Blur()
	switch f.focus {
	case 0:
		f.host.Focus()
	case 1:
		f.ports.Focus()
	}
}

func (f *targetForm) updateInputs(msg tea.Msg) tea.Cmd {
	var c1, c2 tea.Cmd
	f.host, c1 = f.host.Update(msg)
	f.ports, c2 = f.ports.Update(msg)
	return tea.Batch(c1, c2)
}

func (m *model) updateForm(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.form
	switch k.String() {
	case "esc":
		m.form = nil
		return m, nil
	case "tab", "down":
		f.setFocus(f.focus + 1)
		return m, nil
	case "shift+tab", "up":
		f.setFocus(f.focus - 1)
		return m, nil
	case "enter":
		m.submitForm()
		return m, nil
	}
	if f.focus == 2 {
		switch k.String() {
		case "left", "h":
			f.proto = (f.proto + 3) % 4
		case "right", "l", " ":
			f.proto = (f.proto + 1) % 4
		case "a":
			f.proto = ProtoAny
		case "t":
			f.proto = ProtoTCP
		case "u":
			f.proto = ProtoUDP
		case "i":
			f.proto = ProtoICMP
		}
		return m, nil
	}
	f.err = ""
	return m, f.updateInputs(k)
}

func (m *model) submitForm() {
	f := m.form
	host := strings.TrimSpace(f.host.Value())
	ports := strings.TrimSpace(f.ports.Value())
	proto := f.proto.String()
	if fields := strings.Fields(host); len(fields) > 1 { // "8.8.8.8:53 udp" typed in one go
		host = fields[0]
		proto = fields[1]
	}
	if ports == "" {
		host, ports = SplitHostPorts(host)
	}
	spec, err := ParseTarget(host, ports, proto)
	if err != nil {
		f.err = err.Error()
		return
	}
	for i, t := range m.targets {
		if i != f.editIdx && t.Spec.String() == spec.String() {
			f.err = "already tracking " + spec.String()
			return
		}
	}
	if f.editIdx >= 0 && f.editIdx < len(m.targets) {
		m.targets[f.editIdx] = NewTarget(m.targets[f.editIdx].ID, spec)
		m.setStatus("Updated target: "+spec.String(), false)
	} else {
		m.addTarget(spec)
		m.sel = len(m.targets) - 1
		m.setStatus("Now tracking "+spec.String(), false)
	}
	m.form = nil
	m.applyTargets()
}

func (f *targetForm) view(w, h int) string {
	title := "Add target"
	if f.editIdx >= 0 {
		title = "Edit target"
	}
	acc := fg(colFocus).Bold(true)
	label := func(i int, s string) string {
		if f.focus == i {
			return acc.Render("▸ " + s)
		}
		return "  " + s
	}
	field := func(i int, ti textinput.Model) string {
		b := fg(colBorder)
		if f.focus == i {
			b = fg(colFocus)
		}
		return b.Render("[ ") + fit(ti.View(), 43) + b.Render(" ]")
	}
	var protos []string
	for p := ProtoAny; p <= ProtoICMP; p++ {
		if p == f.proto {
			protos = append(protos, acc.Reverse(f.focus == 2).Render(" "+p.String()+" "))
		} else {
			protos = append(protos, dim(" "+p.String()+" "))
		}
	}
	ind := "                "
	lines := []string{
		"",
		label(0, "Host / IP   ") + field(0, f.host),
		dim(ind + "IPv4, IPv6, CIDR range or hostname — host:port works too"),
		"",
		label(1, "Ports       ") + field(1, f.ports),
		dim(ind + "single, list, range or service name; blank = every port"),
		"",
		label(2, "Protocol    ") + "  " + strings.Join(protos, " "),
		dim(ind + "←/→ to change · icmp = ping & errors (no ports)"),
		"",
		dim("  Examples:  1.1.1.1:443    8.8.8.8:53 udp    192.168.1.0/24:22    github.com:https"),
		"",
	}
	if f.err != "" {
		lines = append(lines, fg(colErr).Render("  ✖ "+f.err))
	} else {
		lines = append(lines, "")
	}
	lines = append(lines, "", "  "+keyHint("enter", "save")+"  "+keyHint("tab", "next field")+"  "+keyHint("esc", "cancel"))
	bw := min(w, 90)
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, box(title, lines, bw, len(lines)+2, true))
}

func keyHint(k, desc string) string {
	return fg(colFocus).Bold(true).Render(k) + " " + dim(desc)
}

// ---- view ---------------------------------------------------------------------

func (m *model) View() string {
	if m.width == 0 {
		return "starting…"
	}
	if m.width < 80 || m.height < 24 {
		return fmt.Sprintf("Terminal too small (%dx%d) — need at least 80x24.", m.width, m.height)
	}
	bodyH := m.height - 2
	lw := 34
	if m.width >= 150 {
		lw = 40
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, m.viewTargets(lw, bodyH), m.viewRight(m.width-lw, bodyH))
	return m.viewHeader() + "\n" + body + "\n" + m.viewFooter()
}

func (m *model) viewHeader() string {
	mode := fg(colOK).Bold(true).Render("● LIVE")
	if m.frozen {
		mode = fg(colWarn).Bold(true).Render("❚❚ FROZEN")
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0f172a")).Background(colFocus).Render(" ◈ pkttrack ")
	left := title + "  " + dim("capturing on ") + m.src.Describe() + dim(" (i)") + "   " + mode
	right := dim(fmt.Sprintf("targets %d  dropped %d   ", len(m.targets), m.src.Dropped()+m.ignored)) + keyHint("?", "help ")
	gap := m.width - ansi.StringWidth(left) - ansi.StringWidth(right)
	return left + strings.Repeat(" ", max(1, gap)) + right
}

func (m *model) viewFooter() string {
	if m.status != "" {
		c := lipgloss.TerminalColor(colOK)
		if m.statusErr {
			c = colErr
		}
		return fit(" "+fg(c).Render(m.status), m.width)
	}
	var h []string
	switch {
	case m.inspect != nil:
		h = []string{keyHint("←/→", "prev/next packet"), keyHint("↑/↓", "scroll"), keyHint("esc", "close")}
	case m.focus == focusLog:
		h = []string{keyHint("↑/↓", "select"), keyHint("enter", "inspect"), keyHint("f", "follow"),
			keyHint("v", "explain"), keyHint("tab", "targets"), keyHint("q", "quit")}
	default:
		h = []string{keyHint("a", "add"), keyHint("e", "edit"), keyHint("d", "delete"), keyHint("t", "send packets"),
			keyHint("i", "interfaces"), keyHint("space", "pause"), keyHint("c", "clear"), keyHint("tab", "packets"), keyHint("v", "explain"), keyHint("q", "quit")}
	}
	return fit(" "+strings.Join(h, "  "), m.width)
}

func (m *model) viewTargets(w, h int) string {
	iw := w - 2
	now := time.Now()
	var lines []string
	if len(m.targets) == 0 {
		lines = []string{"", dim("  Nothing tracked yet."), "", "  Press " + keyHint("a", "") + "to add an", "  IP / port to watch."}
	}
	const per = 4
	visible := max(1, (h-2)/per)
	if m.sel < m.tgtOff {
		m.tgtOff = m.sel
	}
	if m.sel >= m.tgtOff+visible {
		m.tgtOff = m.sel - visible + 1
	}
	for i := m.tgtOff; i < len(m.targets) && i < m.tgtOff+visible; i++ {
		t := m.targets[i]
		marker := "  "
		name := t.Spec.Label()
		if i == m.sel {
			marker = fg(colFocus).Bold(true).Render("▶ ")
			name = fg(colFocus).Bold(true).Render(name)
		} else {
			name = bold(name)
		}
		dot := dim("○")
		switch {
		case t.Paused:
			dot = fg(colWarn).Render("⏸")
		case !t.LastSeen.IsZero() && now.Sub(t.LastSeen) < time.Second:
			dot = fg(colOK).Render("●")
		case !t.LastSeen.IsZero():
			dot = fg(lipgloss.Color("#166534")).Render("●")
		}
		proto := ""
		if t.Spec.Proto != ProtoAny {
			proto = " " + dim(t.Spec.Proto.String())
		}
		sw := max(4, iw-13)
		out := t.rate.series(now.Unix(), sw, 0)
		in := t.rate.series(now.Unix(), sw, 1)
		tot := make([]int, sw)
		mx := 1
		for j := range tot {
			tot[j] = out[j] + in[j]
			mx = max(mx, tot[j])
		}
		cur := tot[len(tot)-2]
		lines = append(lines,
			marker+dot+" "+name+proto,
			"    "+sparkline(tot, mx, colFocus)+dim(fmt.Sprintf(" %d/s", cur)),
			"    "+dim(fmt.Sprintf("%s pkts · %s · %d flows", humanCount(t.Packets), humanBytes(t.Bytes), len(t.Conns))),
			"")
	}
	return box(fmt.Sprintf("Targets (%d)", len(m.targets)), lines, w, h, m.focus == focusTargets && m.inspect == nil)
}

func (m *model) viewRight(w, h int) string {
	if m.showHelp {
		return box("Help", helpLines(), w, h, true)
	}
	if m.form != nil {
		return m.form.view(w, h)
	}
	if m.picker != nil {
		return m.picker.view(m, w, h)
	}
	t := m.current()
	if m.probeForm != nil && t != nil {
		return m.probeForm.view(w, h, t)
	}
	if t == nil {
		return box("Flow", welcomeLines(), w, h, false)
	}
	const flowH = 12
	if m.inspect != nil {
		return m.viewFlow(t, w, flowH) + "\n" + m.viewInspector(w, h-flowH)
	}
	conns := t.RecentConns(5)
	connH := max(1, len(conns)) + 3
	if h-flowH-connH < 6 {
		connH = max(3, h-flowH-6)
	}
	logH := h - flowH - connH
	return m.viewFlow(t, w, flowH) + "\n" + m.viewConns(t, conns, w, connH) + "\n" + m.viewLog(t, w, logH)
}

// lane is one row of the animated wire between the two endpoints.
type lane struct {
	r []rune
	k []Kind
}

func newLane(n int) *lane {
	l := &lane{r: make([]rune, n), k: make([]Kind, n)}
	for i := range l.r {
		l.r[i], l.k[i] = '┄', KNone
	}
	return l
}

func (l *lane) put(x int, s string, k Kind) {
	for i, ch := range []rune(s) {
		if p := x + i; p >= 0 && p < len(l.r) {
			l.r[p], l.k[p] = ch, k
		}
	}
}

func (l *lane) render() string {
	var sb strings.Builder
	start := 0
	for i := 1; i <= len(l.r); i++ {
		if i == len(l.r) || l.k[i] != l.k[start] {
			st := fg(colBorder)
			if l.k[start] != KNone {
				st = kc(l.k[start]).Bold(true)
			}
			sb.WriteString(st.Render(string(l.r[start:i])))
			start = i
		}
	}
	return sb.String()
}

func (m *model) viewFlow(t *Target, w, h int) string {
	iw := w - 2
	now := time.Now()
	ago := "never"
	if !t.LastSeen.IsZero() {
		ago = "just now"
		if d := now.Sub(t.LastSeen); d >= time.Second {
			ago = fmtDur(d.Truncate(100*time.Millisecond)) + " ago"
		}
	}
	lines := []string{
		fmt.Sprintf(" %s pkts   %s   %s %s   %s %s   %d flows   last packet %s",
			bold(humanCount(t.Packets)), humanBytes(t.Bytes),
			fg(colOut).Render("▶"), humanCount(t.Pkts[0]), fg(colIn).Render("◀"), humanCount(t.Pkts[1]),
			len(t.Conns), ago),
	}
	sw := min(rateWindow, max(10, iw-26))
	out := t.rate.series(now.Unix(), sw, 0)
	in := t.rate.series(now.Unix(), sw, 1)
	mx := 1
	for i := range out {
		mx = max(mx, out[i], in[i])
	}
	lines = append(lines,
		" "+fg(colOut).Render("to target   ")+sparkline(out, mx, colOut)+fmt.Sprintf(" %4d/s", out[sw-2]),
		" "+fg(colIn).Render("from target ")+sparkline(in, mx, colIn)+fmt.Sprintf(" %4d/s", in[sw-2]))

	// Animated wire: packets travel between the PEER and TARGET boxes.
	const bw = 10
	L := max(10, iw-2*bw-2)
	outLane, inLane := newLane(L), newLane(L)
	peerFlash, tgtFlash := KNone, KNone
	for _, s := range t.sprites {
		age := now.Sub(s.Born)
		if age >= travelTime {
			if age < travelTime+flashTime {
				if s.ToTarget {
					tgtFlash = s.Kind
				} else {
					peerFlash = s.Kind
				}
			}
			continue
		}
		tok := "◀" + s.Label
		if s.ToTarget {
			tok = s.Label + "▶"
		}
		span := max(0, L-len([]rune(tok)))
		x := int(float64(age) / float64(travelTime) * float64(span))
		if s.ToTarget {
			outLane.put(x, tok, s.Kind)
		} else {
			inLane.put(span-x, tok, s.Kind)
		}
	}
	bs := func(k Kind) lipgloss.Style {
		if k != KNone {
			return kc(k).Bold(true)
		}
		return fg(colDim)
	}
	pb, tb := bs(peerFlash), bs(tgtFlash)
	peerName := "PEER"
	if host, _, err := net.SplitHostPort(t.LastPeer); (err == nil && localIPs[host]) || localIPs[t.LastPeer] {
		peerName = "YOU"
	}
	gap := strings.Repeat(" ", L)
	lines = append(lines, "",
		" "+pb.Render("╭────────╮")+gap+tb.Render("╭────────╮"),
		" "+pb.Render("│")+center(bold(peerName), 8)+pb.Render("│")+outLane.render()+tb.Render("│")+center(bold("TARGET"), 8)+tb.Render("│"),
		" "+pb.Render("│")+center(dim("tx "+humanCount(t.Pkts[0])), 8)+pb.Render("│")+inLane.render()+tb.Render("│")+center(dim("tx "+humanCount(t.Pkts[1])), 8)+tb.Render("│"),
		" "+pb.Render("╰────────╯")+gap+tb.Render("╰────────╯"),
	)
	pl, tl := t.LastPeer, t.LastTgt
	if pl == "" {
		pl, tl = "waiting for packets…", t.Spec.Label()
	}
	half := iw / 2
	lines = append(lines, " "+fit(dim(pl), half-1)+fitRight(dim(tl), iw-half))
	lines = append(lines, m.probeLine(t, iw))

	title := "Flow · " + t.Spec.String()
	if t.Paused {
		title += " (paused)"
	}
	return box(title, lines, w, h, false)
}

func pipeline(c *Conn) string {
	switch c.Key.Proto {
	case ProtoTCP:
		stages := []struct {
			bit  uint8
			name string
			k    Kind
		}{{stgSYN, "SYN", KSyn}, {stgSYNACK, "SYN/ACK", KSynAck}, {stgACK, "ACK", KSyn},
			{stgDATA, "DATA", KData}, {stgFIN, "FIN", KFin}, {stgCLOSED, "DONE", KFin}}
		var parts []string
		for i, s := range stages {
			switch {
			case c.Stages&s.bit != 0:
				parts = append(parts, kc(s.k).Render("●"+s.name))
			case c.Midstream && i < 3:
				parts = append(parts, dim("◌"+s.name))
			default:
				parts = append(parts, dim("○"+s.name))
			}
		}
		p := strings.Join(parts, dim("─"))
		if c.RST {
			p += " " + kc(KRst).Bold(true).Render("✖RST")
		}
		if c.Retrans > 0 {
			p += " " + kc(KRetrans).Render(fmt.Sprintf("retx×%d", c.Retrans))
		}
		return p
	case ProtoUDP:
		return kc(KUDP).Render("● datagrams") + "  " + dim(c.LastInfo)
	}
	return kc(KICMP).Render("● icmp") + "  " + dim(c.LastInfo)
}

func (m *model) viewConns(t *Target, conns []*Conn, w, h int) string {
	now := time.Now()
	lines := []string{dim(fmt.Sprintf(" %-23s %-5s %-12s %-11s %-9s %s", "PEER", "PROTO", "STATE", "PKTS ▶/◀", "RTT", "LIFECYCLE"))}
	if len(conns) == 0 {
		lines = append(lines, dim(" no flows yet"))
	}
	for _, c := range conns {
		peer := c.Key.Peer
		if now.Sub(c.Last) > 10*time.Second {
			peer = dim(peer)
		}
		rtt := "-"
		if c.RTT > 0 {
			rtt = fmtDur(c.RTT)
		}
		state := fg(stateColors[c.State]).Bold(true).Render(c.State.String())
		lines = append(lines, " "+fit(peer, 23)+" "+fit(strings.ToUpper(c.Key.Proto.String()), 5)+" "+fit(state, 12)+" "+
			fit(fmt.Sprintf("%d/%d", c.Pkts[0], c.Pkts[1]), 11)+" "+fit(rtt, 9)+" "+pipeline(c))
	}
	return box(fmt.Sprintf("Flows (%d, newest first)", len(t.Conns)), lines, w, h, false)
}

func arrow(lp *LoggedPacket, w int) string {
	label := lp.Short
	if lp.Ev.Proto == ProtoTCP {
		label = lp.Flags
		if lp.Ev.Payload > 0 {
			label += " " + humanBytes(lp.Ev.Payload)
		}
	} else if lp.Ev.Payload > 0 && lp.Ev.Proto == ProtoUDP {
		label += " " + humanBytes(lp.Ev.Payload)
	}
	if lp.Retrans {
		label = "RETX " + label
	}
	label = ansi.Truncate(label, w-6, "…")
	fill := strings.Repeat("─", max(1, w-5-ansi.StringWidth(label)))
	var s string
	if lp.ToTarget {
		s = "── " + label + " " + fill + "▶"
	} else {
		s = "◀" + fill + " " + label + " ──"
	}
	return kc(lp.Kind).Render(s)
}

func (m *model) viewLog(t *Target, w, h int) string {
	iw := w - 2
	rows := max(1, h-3)
	n := len(t.Log)
	if m.follow || t.logCursor >= n {
		t.logCursor = n - 1
	}
	if m.follow {
		t.logOff = max(0, n-rows)
	} else {
		if t.logCursor < t.logOff {
			t.logOff = t.logCursor
		}
		if t.logCursor >= t.logOff+rows {
			t.logOff = t.logCursor - rows + 1
		}
	}
	short := t.Spec.SingleHost()
	tw := 21
	if short {
		tw = 6
	}
	detail := "DETAILS"
	if m.explain {
		detail = "WHAT IT'S DOING"
	}
	multi := false
	if is, ok := m.src.(ifaceSource); ok && len(is.Interfaces()) > 1 {
		multi = true
	}
	ifHead := ""
	if multi {
		ifHead = fmt.Sprintf("%-7s ", "IF")
	}
	lines := []string{dim(fmt.Sprintf("  %-12s %s%-8s %21s %-26s %-*s %s", "TIME", ifHead, "Δ", "PEER", "  PACKET", tw, "TARGET", detail))}
	if n == 0 {
		lines = append(lines, "", dim("  Waiting for matching packets… (generate some traffic to "+t.Spec.Label()+")"))
	}
	for i := t.logOff; i < n && i < t.logOff+rows; i++ {
		lp := t.Log[i]
		marker := "  "
		if i == t.logCursor && m.focus == focusLog {
			marker = fg(colFocus).Bold(true).Render("▶ ")
		}
		dt := ""
		if lp.Delta > 0 {
			dt = "+" + fmtDur(lp.Delta)
		}
		tgt := lp.Conn.Key.Target
		if short {
			if _, p, err := net.SplitHostPort(tgt); err == nil {
				tgt = ":" + p
			} else {
				tgt = "·"
			}
		}
		note := ""
		if m.probe.peers[lp.Conn.Key.Peer] {
			note = fg(colWarn).Bold(true).Render("⚑probe") + " "
		}
		if lp.Note != "" {
			c := lipgloss.TerminalColor(colOK)
			if lp.Kind == KRst || lp.Kind == KRetrans || lp.Kind == KICMPErr || strings.Contains(lp.Note, "zero") {
				c = colErr
			}
			note += fg(c).Bold(true).Render("["+lp.Note+"]") + " "
		}
		info := lp.Info
		if m.explain { // the addresses are already in the PEER/TARGET columns
			info = strings.Replace(lp.Explain, "Peer "+lp.Conn.Key.Peer, "Peer", 1)
			info = strings.Replace(info, "Target "+lp.Conn.Key.Target, "Target", 1)
		}
		ifCol := ""
		if multi {
			ifCol = fit(fg(colFocus).Render(lp.Ev.Iface), 7) + " "
		}
		lines = append(lines, marker+lp.Ev.Time.Format("15:04:05.000")+" "+ifCol+fit(dim(dt), 8)+" "+
			fitRight(lp.Conn.Key.Peer, 21)+" "+arrow(lp, 26)+" "+fit(tgt, tw)+" "+note+dim(info))
	}
	title := fmt.Sprintf("Packets (%d)", n)
	if !m.follow {
		title += " · scrolled (f to follow)"
	}
	_ = iw
	return box(title, lines, w, h, m.focus == focusLog)
}

func (m *model) viewInspector(w, h int) string {
	rows := h - 2
	end := min(len(m.inspLines), m.inspOff+rows)
	var lines []string
	for _, l := range m.inspLines[m.inspOff:end] {
		switch {
		case l == "WHAT IT'S DOING" || l == "LAYERS" || strings.HasPrefix(l, "HEX DUMP"):
			lines = append(lines, fg(colFocus).Bold(true).Render(l))
		case strings.HasPrefix(l, "  0") && len(l) > 6 && l[6] == ' ':
			lines = append(lines, dim(l))
		default:
			lines = append(lines, l)
		}
	}
	lp := m.inspect
	title := fmt.Sprintf("Inspect · %s %s %s", lp.Ev.Time.Format("15:04:05.000"),
		map[bool]string{true: "peer ▶ target", false: "target ◀ peer"}[lp.ToTarget], lp.Short)
	return box(title, lines, w, h, true)
}

func welcomeLines() []string {
	return []string{
		"",
		bold("  Welcome to pkttrack"),
		"",
		"  Track specific packets to and from the IPs and ports you care about,",
		"  and watch what each packet is doing in real time:",
		"",
		"   • an animated wire shows every packet travelling between peer and target",
		"   • the flow table follows each TCP connection through its lifecycle",
		"     " + kc(KSyn).Render("●SYN") + dim("─") + kc(KSynAck).Render("●SYN/ACK") + dim("─") + kc(KSyn).Render("●ACK") + dim("─") +
			kc(KData).Render("●DATA") + dim("─") + kc(KFin).Render("●FIN") + dim("─") + kc(KFin).Render("●DONE"),
		"   • the packet ladder lists every packet; press v for plain-English",
		"   • press enter on a packet to dissect its layers and hex",
		"",
		"  Press " + keyHint("a", "") + "to add your first target.",
	}
}

func helpLines() []string {
	row := func(k, d string) string { return "   " + fit(fg(colFocus).Bold(true).Render(k), 14) + d }
	sw := func(k Kind, d string) string { return "   " + fit(kc(k).Bold(true).Render("■ "+d), 20) }
	return []string{
		"",
		bold("  Targets"),
		row("a", "add a target (IP, CIDR, hostname + ports + protocol)"),
		row("e", "edit selected target"),
		row("d", "delete selected target  (u undoes)"),
		row("space", "pause / resume capture for selected target"),
		row("c", "clear its counters, flows and log"),
		row("i", "choose capture interfaces (one, several, or all)"),
		row("t", "send test packets: choose IP, port, tcp/udp/icmp, count, payload"),
		row("T / s", "re-send the last probe immediately / stop a running probe"),
		row("1-9 ↑/↓", "select target"),
		"",
		bold("  Packets"),
		row("tab", "switch focus between targets and packet list"),
		row("↑/↓ pgup/pgdn", "move through packets"),
		row("enter", "inspect packet (layers + hex); ←/→ steps packets"),
		row("f / G", "follow newest packets"),
		row("v", "toggle plain-English explanations"),
		row("p", "freeze / unfreeze the whole display"),
		row("q", "quit"),
		"",
		bold("  Colours"),
		sw(KSyn, "SYN") + sw(KSynAck, "SYN+ACK") + sw(KAck, "ACK") + sw(KData, "DATA"),
		sw(KFin, "FIN") + sw(KRst, "RST") + sw(KRetrans, "retransmit") + sw(KUDP, "UDP"),
		sw(KICMP, "ICMP") + sw(KICMPErr, "ICMP error"),
		"",
		dim("  press any key to close"),
	}
}
