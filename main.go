package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, "; ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	var targets multiFlag
	iface := flag.String("i", "", "interface(s) to capture on: en0 · en0,lo0 · all (default: last used, else the default-route one)")
	flag.Var(&targets, "t", `target to track, e.g. -t "8.8.8.8:53 udp" (repeatable)`)
	demo := flag.Bool("demo", false, "simulate traffic instead of capturing (no root needed)")
	cfg := flag.String("config", defaultConfigPath(), "file where targets are loaded from and saved to (\"\" disables)")
	promisc := flag.Bool("promisc", false, "put the interface in promiscuous mode")
	snaplen := flag.Int("snaplen", 2048, "bytes to capture per packet")
	list := flag.Bool("list", false, "list capture interfaces and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `pkttrack — watch packets to/from specific IPs and ports

Usage:
  sudo pkttrack [flags]
  pkttrack -demo

Target syntax:  host[:ports] [proto]
  1.1.1.1:443              one host, one port
  10.0.0.5:22,80,8000-8100 list and ranges
  192.168.1.0/24           a whole subnet, any port
  [2001:db8::1]:443 tcp    IPv6
  github.com:https         hostnames and service names
  8.8.8.8 icmp             pings and ICMP errors only

Flags:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *list {
		if err := listInterfaces(); err != nil {
			fail(err)
		}
		return
	}

	cfgSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			cfgSet = true
		}
	})
	if *demo && !cfgSet {
		*cfg = "" // don't let demo targets overwrite your saved list
	}

	var specs []TargetSpec
	seen := map[string]bool{}
	var warnings []string
	add := func(line string, fatal bool) {
		s, err := ParseTargetLine(line)
		if err != nil {
			if fatal {
				fail(fmt.Errorf("target %q: %w", line, err))
			}
			warnings = append(warnings, fmt.Sprintf("%q: %v", line, err))
			return
		}
		if !seen[s.String()] {
			seen[s.String()] = true
			specs = append(specs, s)
		}
	}
	savedIfaces := ""
	if *cfg != "" {
		lines, err := loadConfig(*cfg)
		if err != nil {
			warnings = append(warnings, "reading "+*cfg+": "+err.Error())
		}
		for _, l := range lines {
			if v, ok := strings.CutPrefix(l, ifaceDirective); ok {
				savedIfaces = strings.TrimSpace(v)
				continue
			}
			add(l, false)
		}
	}
	for _, t := range targets {
		add(t, true)
	}

	var src Source
	ifaceSetting := savedIfaces
	var notes []string
	if *demo {
		if len(specs) == 0 {
			for _, l := range []string{"1.1.1.1:443", "8.8.8.8:53 udp", "192.168.1.1 icmp", "10.0.0.0/24:22,80"} {
				add(l, true)
			}
		}
		src = NewDemoSource()
	} else {
		setting := savedIfaces
		if *iface != "" {
			setting = *iface
		}
		var names []string
		if setting != "" {
			names = strings.Split(setting, ",")
		}
		ps, warns, err := OpenPcap(names, *snaplen, *promisc)
		if err != nil && *iface == "" && savedIfaces != "" && !strings.Contains(err.Error(), "ermission") {
			// saved interfaces vanished (VPN down, adapter unplugged): fall back to the default
			notes = append(notes, "saved interfaces "+savedIfaces+" unavailable, using default")
			ps, warns, err = OpenPcap(nil, *snaplen, *promisc)
			setting = ""
		}
		notes = append(notes, warns...)
		if *iface != "" {
			ifaceSetting = savedIfaces // a one-off -i doesn't change what's remembered
		}
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "ermission") || strings.Contains(msg, "/dev/bpf") {
				msg += "\n\nPacket capture needs elevated privileges. Try:\n  sudo " + strings.Join(os.Args, " ") +
					"\nor run with -demo to try it with simulated traffic."
			}
			fail(fmt.Errorf("%s", msg))
		}
		src = ps
	}
	defer src.Close()

	notice := ""
	switch {
	case len(warnings) > 0:
		notice = "warning: skipped bad saved targets: " + strings.Join(warnings, "; ")
	case len(notes) > 0:
		notice = "warning: " + strings.Join(notes, "; ")
	case *demo:
		notice = "Demo mode: simulated traffic. Press a to add your own targets."
	}

	m := newModel(src, specs, *cfg, notice)
	m.ifaceSetting = ifaceSetting
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "pkttrack:", err)
	os.Exit(1)
}
