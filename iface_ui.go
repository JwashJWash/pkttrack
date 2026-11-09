package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ifacePicker is the multi-select list of capture interfaces.
type ifacePicker struct {
	devs    []DeviceInfo
	sel     map[string]bool
	cursor  int
	off     int
	allMode bool // "a" was used: remember as "all" so new interfaces are picked up next time
	err     string
}

func (m *model) openIfacePicker() {
	devs, err := ListDevices()
	p := &ifacePicker{sel: map[string]bool{}, allMode: strings.EqualFold(m.ifaceSetting, "all")}
	if err != nil {
		p.err = "cannot list interfaces: " + err.Error()
	}
	p.devs = devs
	if is, ok := m.src.(ifaceSource); ok {
		for _, n := range is.Interfaces() {
			p.sel[n] = true
		}
	}
	m.picker = p
}

func (m *model) updatePicker(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	p := m.picker
	switch k.String() {
	case "esc", "q", "i":
		m.picker = nil
	case "up", "k":
		p.cursor = max(0, p.cursor-1)
	case "down", "j":
		p.cursor = min(len(p.devs)-1, p.cursor+1)
	case "home", "g":
		p.cursor = 0
	case "end", "G":
		p.cursor = len(p.devs) - 1
	case " ", "x":
		if p.cursor < len(p.devs) {
			n := p.devs[p.cursor].Name
			p.sel[n] = !p.sel[n]
			p.allMode = false
			p.err = ""
		}
	case "a":
		p.sel = map[string]bool{}
		for _, d := range p.devs {
			if d.Active() {
				p.sel[d.Name] = true
			}
		}
		p.allMode, p.err = true, ""
	case "A":
		p.sel = map[string]bool{}
		for _, d := range p.devs {
			p.sel[d.Name] = true
		}
		p.allMode, p.err = false, ""
	case "n":
		p.sel, p.allMode = map[string]bool{}, false
	case "d":
		p.sel, p.allMode = map[string]bool{}, false
		for _, d := range p.devs {
			if d.Default {
				p.sel[d.Name] = true
			}
		}
	case "enter":
		m.applyPicker()
	}
	return m, nil
}

func (m *model) applyPicker() {
	p := m.picker
	is, ok := m.src.(ifaceSource)
	if !ok {
		p.err = "interface selection needs live capture — you're in -demo mode"
		return
	}
	var names []string
	for _, d := range p.devs { // keep the list's order
		if p.sel[d.Name] {
			names = append(names, d.Name)
		}
	}
	if len(names) == 0 {
		p.err = "select at least one interface (space toggles, a = all active)"
		return
	}
	opened, failed := is.SetInterfaces(names)
	if len(opened) == 0 {
		p.err = "none of the selected interfaces could be opened"
		for n, e := range failed {
			p.err += fmt.Sprintf("; %s: %v", n, e)
		}
		return
	}
	m.src.Update(m.activeSpecs()) // make sure every reader has the current filter
	if p.allMode {
		m.ifaceSetting = "all"
	} else {
		m.ifaceSetting = strings.Join(opened, ",")
	}
	m.applyTargets() // persists the selection
	msg := "Capturing on " + strings.Join(opened, ", ")
	if len(failed) > 0 {
		var f []string
		for n, e := range failed {
			f = append(f, n+" ("+e.Error()+")")
		}
		m.setStatus(msg+" — could not open "+strings.Join(f, ", "), true)
	} else {
		m.setStatus(msg, false)
	}
	m.picker = nil
}

func (p *ifacePicker) view(m *model, w, h int) string {
	is, live := m.src.(ifaceSource)
	acc := fg(colFocus).Bold(true)
	bw := min(w, 104)
	iw := bw - 2
	lines := []string{
		dim("  Choose which interfaces to capture on. Packets from all selected interfaces are merged;"),
		dim("  the same packet seen on two interfaces (e.g. a bridge and its port) is only counted once."),
		"",
	}
	rows := max(3, h-12)
	if p.cursor < p.off {
		p.off = p.cursor
	}
	if p.cursor >= p.off+rows {
		p.off = p.cursor - rows + 1
	}
	if len(p.devs) == 0 {
		lines = append(lines, dim("  no interfaces found"))
	}
	for i := p.off; i < len(p.devs) && i < p.off+rows; i++ {
		d := p.devs[i]
		cur := "  "
		if i == p.cursor {
			cur = acc.Render("▶ ")
		}
		box := dim("[ ]")
		if p.sel[d.Name] {
			box = fg(colOK).Bold(true).Render("[x]")
		}
		name := fit(bold(d.Name), 10)
		if i == p.cursor {
			name = fit(acc.Render(d.Name), 10)
		}
		state := dim("○ inactive")
		switch {
		case d.Default:
			state = fg(colOK).Render("● default")
		case d.Active():
			state = fg(colOK).Render("● up")
		case d.Up && len(d.Addrs) > 0:
			state = dim("● link-local only")
		case d.Up:
			state = dim("● up, no address")
		}
		count := ""
		if live {
			if c := is.IfaceCount(d.Name); c > 0 {
				count = dim(humanCount(int(c)) + " pkts")
			}
		}
		addrs := strings.Join(d.Addrs, " · ")
		if addrs == "" {
			addrs = "—"
		}
		lines = append(lines, cur+box+" "+name+" "+fit(d.Kind, 20)+" "+fit(state, 17)+" "+fit(count, 11)+" "+dim(addrs))
	}
	if len(p.devs) > rows {
		lines = append(lines, dim(fmt.Sprintf("  … %d interfaces, ↑/↓ to scroll", len(p.devs))))
	}
	n := 0
	for _, v := range p.sel {
		if v {
			n++
		}
	}
	sel := fmt.Sprintf("%d selected", n)
	if p.allMode {
		sel += " (all active — remembered as \"all\")"
	}
	lines = append(lines, "", "  "+acc.Render(sel))
	if p.err != "" {
		lines = append(lines, fg(colErr).Render("  ✖ "+p.err))
	} else {
		lines = append(lines, "")
	}
	lines = append(lines, "  "+keyHint("space", "toggle")+"  "+keyHint("a", "all active")+"  "+keyHint("A", "every")+"  "+keyHint("d", "default only")+"  "+
		keyHint("n", "none")+"  "+keyHint("enter", "apply")+"  "+keyHint("esc", "cancel"))
	for i := range lines {
		lines[i] = fit(lines[i], iw)
	}
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, box("Capture interfaces", lines, bw, min(h, len(lines)+2), true))
}
