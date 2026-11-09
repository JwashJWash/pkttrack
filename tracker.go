package main

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"
)

// Kind classifies a packet for colouring and animation.
type Kind int

const (
	KNone Kind = iota - 1
	KAck
	KSyn
	KSynAck
	KData
	KFin
	KRst
	KRetrans
	KUDP
	KICMP
	KICMPErr
)

type ConnState int

const (
	StNew ConnState = iota
	StSynSent
	StSynRcvd
	StEstablished
	StFinWait
	StClosing
	StClosed
	StReset
	StRefused
	StActive
)

var stateNames = map[ConnState]string{
	StNew: "NEW", StSynSent: "SYN_SENT", StSynRcvd: "SYN_RCVD", StEstablished: "ESTABLISHED",
	StFinWait: "FIN_WAIT", StClosing: "CLOSING", StClosed: "CLOSED", StReset: "RESET",
	StRefused: "REFUSED", StActive: "ACTIVE",
}

func (s ConnState) String() string { return stateNames[s] }

// TCP lifecycle stages, used for the progress pipeline.
const (
	stgSYN uint8 = 1 << iota
	stgSYNACK
	stgACK
	stgDATA
	stgFIN
	stgCLOSED
)

type FlowKey struct {
	Proto        Proto
	Peer, Target string
}

// Conn is one flow between a peer and the target.
type Conn struct {
	Key       FlowKey
	State     ConnState
	Stages    uint8
	RST       bool
	Midstream bool // we joined after the handshake
	First     time.Time
	Last      time.Time
	Pkts      [2]int // [0] toward target, [1] from target
	Bytes     [2]int
	Retrans   int
	RTT       time.Duration
	LastInfo  string

	clientDir int
	isn       [2]uint32
	haveISN   [2]bool
	nextSeq   [2]uint32
	haveNext  [2]bool
	finSeen   [2]bool
	synTime   time.Time
	lastSent  [2]time.Time
	echo      map[uint32]time.Time
}

// LoggedPacket is one row in the packet ladder.
type LoggedPacket struct {
	Ev       *PacketEvent
	ToTarget bool
	Conn     *Conn
	Kind     Kind
	Short    string // label for the animation, e.g. "SYN"
	Flags    string
	RelSeq   uint32
	RelAck   uint32
	Retrans  bool
	Delta    time.Duration // since previous packet in this flow
	Info     string        // technical summary
	Note     string        // highlight: RTT, retransmission...
	Explain  string        // plain-English description
}

type Sprite struct {
	Born     time.Time
	ToTarget bool
	Kind     Kind
	Label    string
}

const (
	maxLog     = 2000
	logTrim    = 250
	maxConns   = 256
	maxSprites = 48
	rateWindow = 120
)

type rateRing struct {
	b    [rateWindow][2]int
	head int64
}

func (r *rateRing) advance(sec int64) {
	if r.head == 0 {
		r.head = sec
		return
	}
	if sec <= r.head {
		return
	}
	n := sec - r.head
	if n > rateWindow {
		n = rateWindow
	}
	for i := int64(1); i <= n; i++ {
		r.b[(r.head+i)%rateWindow] = [2]int{}
	}
	r.head = sec
}

func (r *rateRing) add(sec int64, dir int) {
	r.advance(sec)
	if sec <= r.head-rateWindow {
		return
	}
	r.b[sec%rateWindow][dir]++
}

func (r *rateRing) series(now int64, n, dir int) []int {
	r.advance(now)
	out := make([]int, n)
	for i := 0; i < n; i++ {
		s := now - int64(n-1-i)
		if s <= r.head-rateWindow || s > r.head {
			continue
		}
		out[i] = r.b[s%rateWindow][dir]
	}
	return out
}

// Target is a watched spec plus everything we've learned about it.
type Target struct {
	ID       int
	Spec     TargetSpec
	Paused   bool
	Packets  int
	Bytes    int
	Pkts     [2]int
	LastSeen time.Time
	LastPeer string
	LastTgt  string

	ProbeLast string
	ProbeOK   bool
	ProbeAt   time.Time
	Conns     map[FlowKey]*Conn
	Log       []*LoggedPacket

	rate      rateRing
	sprites   []Sprite
	logCursor int
	logOff    int
}

func NewTarget(id int, spec TargetSpec) *Target {
	return &Target{ID: id, Spec: spec, Conns: map[FlowKey]*Conn{}}
}

func hostPort(ip net.IP, port uint16, p Proto) string {
	if p == ProtoICMP {
		return ip.String()
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func (t *Target) Ingest(ev *PacketEvent, toTarget bool, now time.Time) {
	dir := 0
	peerIP, peerPort, tgtIP, tgtPort := ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort
	if !toTarget {
		dir = 1
		peerIP, peerPort, tgtIP, tgtPort = ev.DstIP, ev.DstPort, ev.SrcIP, ev.SrcPort
	}
	key := FlowKey{Proto: ev.Proto, Peer: hostPort(peerIP, peerPort, ev.Proto), Target: hostPort(tgtIP, tgtPort, ev.Proto)}
	c := t.Conns[key]
	if c == nil {
		c = &Conn{Key: key, First: ev.Time, clientDir: -1}
		t.evictConns()
		t.Conns[key] = c
	}
	lp := &LoggedPacket{Ev: ev, ToTarget: toTarget, Conn: c}
	if !c.Last.IsZero() {
		lp.Delta = ev.Time.Sub(c.Last)
	}
	who := "Peer " + key.Peer
	if dir == 1 {
		who = "Target " + key.Target
	}
	switch ev.Proto {
	case ProtoTCP:
		c.handleTCP(ev, dir, lp, who)
	case ProtoUDP:
		c.handleUDP(ev, dir, lp, who)
	case ProtoICMP:
		c.handleICMP(ev, dir, lp, who)
	}
	c.Last = ev.Time
	c.Pkts[dir]++
	c.Bytes[dir] += ev.Size
	if ev.Info != "" {
		c.LastInfo = ev.Info
	}
	t.Packets++
	t.Bytes += ev.Size
	t.Pkts[dir]++
	t.LastSeen = now
	t.LastPeer, t.LastTgt = key.Peer, key.Target
	t.rate.add(now.Unix(), dir)

	t.Log = append(t.Log, lp)
	if len(t.Log) > maxLog+logTrim {
		t.Log = append([]*LoggedPacket(nil), t.Log[logTrim:]...)
		t.logCursor = max(0, t.logCursor-logTrim)
		t.logOff = max(0, t.logOff-logTrim)
	}
	t.sprites = append(t.sprites, Sprite{Born: now, ToTarget: toTarget, Kind: lp.Kind, Label: lp.Short})
	if len(t.sprites) > maxSprites {
		t.sprites = t.sprites[len(t.sprites)-maxSprites:]
	}
}

func (t *Target) prune(now time.Time) {
	keep := t.sprites[:0]
	for _, s := range t.sprites {
		if now.Sub(s.Born) < travelTime+flashTime {
			keep = append(keep, s)
		}
	}
	t.sprites = keep
}

func (t *Target) evictConns() {
	if len(t.Conns) < maxConns {
		return
	}
	var victim *Conn
	for _, c := range t.Conns {
		done := c.State == StClosed || c.State == StReset || c.State == StRefused
		if victim == nil {
			victim = c
			continue
		}
		vDone := victim.State == StClosed || victim.State == StReset || victim.State == StRefused
		if (done && !vDone) || (done == vDone && c.Last.Before(victim.Last)) {
			victim = c
		}
	}
	delete(t.Conns, victim.Key)
}

func (t *Target) RecentConns(n int) []*Conn {
	all := make([]*Conn, 0, len(t.Conns))
	for _, c := range t.Conns {
		all = append(all, c)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Last.After(all[j].Last) })
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func (c *Conn) resetTCP() {
	*c = Conn{Key: c.Key, First: c.First, Pkts: c.Pkts, Bytes: c.Bytes, clientDir: -1}
}

func (c *Conn) handleTCP(ev *PacketEvent, dir int, lp *LoggedPacket, who string) {
	f := ev.Flags
	other := 1 - dir
	isSyn, isAck, isFin, isRst := f&FlagSYN != 0, f&FlagACK != 0, f&FlagFIN != 0, f&FlagRST != 0

	// A fresh SYN on a flow we already finished = the 4-tuple is being reused.
	if isSyn && !isAck && c.State != StNew && c.State != StSynSent {
		c.resetTCP()
	}
	if !c.haveISN[dir] {
		c.isn[dir], c.haveISN[dir] = ev.Seq, true
		if !isSyn && c.State == StNew {
			c.Midstream = true
		}
	}
	lp.RelSeq = ev.Seq - c.isn[dir]
	if isAck && c.haveISN[other] {
		lp.RelAck = ev.Ack - c.isn[other]
	}
	segLen := uint32(ev.Payload)
	if isSyn {
		segLen++
	}
	if isFin {
		segLen++
	}
	end := ev.Seq + segLen
	if ev.Payload > 0 && c.haveNext[dir] && int32(end-c.nextSeq[dir]) <= 0 {
		lp.Retrans = true
	}
	if isSyn && !isAck && c.State == StSynSent && c.Stages&stgSYN != 0 {
		lp.Retrans = true
	}
	if !c.haveNext[dir] || int32(end-c.nextSeq[dir]) > 0 {
		c.nextSeq[dir], c.haveNext[dir] = end, true
	}
	lp.Flags = f.String()

	switch {
	case isRst:
		lp.Kind, lp.Short = KRst, "RST"
		c.RST = true
		if c.State == StSynSent && dir != c.clientDir {
			c.State = StRefused
			lp.Note = "connection refused"
			lp.Explain = who + " refused the connection — nothing is listening on that port, so it answered the SYN with a reset"
		} else {
			c.State = StReset
			lp.Note = "reset"
			lp.Explain = who + " abruptly aborted the connection with a reset (RST) — no graceful close"
		}
	case isSyn && !isAck:
		lp.Kind, lp.Short = KSyn, "SYN"
		c.State = StSynSent
		c.Stages |= stgSYN
		c.clientDir = dir
		if c.synTime.IsZero() {
			c.synTime = ev.Time
		}
		lp.Explain = who + " asks to open a TCP connection (handshake 1/3: SYN, \"can we talk?\")"
	case isSyn && isAck:
		lp.Kind, lp.Short = KSynAck, "SYN+ACK"
		if c.Stages&stgSYN == 0 {
			c.clientDir = other
		}
		c.Stages |= stgSYNACK
		c.State = StSynRcvd
		if !c.synTime.IsZero() {
			c.RTT = ev.Time.Sub(c.synTime)
			lp.Note = "RTT " + fmtDur(c.RTT)
		}
		lp.Explain = who + " accepts the connection (handshake 2/3: SYN+ACK, \"yes, I'm listening\")"
	case isFin:
		lp.Kind, lp.Short = KFin, "FIN"
		c.finSeen[dir] = true
		c.Stages |= stgFIN
		if ev.Payload > 0 {
			c.Stages |= stgDATA
		}
		if c.finSeen[other] {
			c.State = StClosing
			lp.Explain = who + " finishes too — both sides have now said goodbye (FIN)"
		} else {
			c.State = StFinWait
			lp.Explain = who + " is done sending and starts closing its half of the connection (FIN)"
		}
	default:
		if ev.Payload > 0 {
			lp.Kind, lp.Short = KData, "DATA"
			if ev.App != "" {
				lp.Short = ev.App
			}
			c.Stages |= stgDATA
			lp.Explain = fmt.Sprintf("%s sends %s of application data", who, humanBytes(ev.Payload))
			if ev.Info != "" {
				lp.Explain += " — " + ev.Info
			}
		} else {
			lp.Kind, lp.Short = KAck, "ACK"
			lp.Explain = fmt.Sprintf("%s acknowledges receiving everything up to byte %d", who, lp.RelAck)
		}
		switch c.State {
		case StSynRcvd:
			if dir == c.clientDir {
				c.State = StEstablished
				c.Stages |= stgACK
				lp.Note = "handshake complete"
				lp.Explain = who + " confirms — connection ESTABLISHED (handshake 3/3: ACK)"
			}
		case StNew:
			c.State = StEstablished
			c.Midstream = true
		case StClosing:
			if ev.Payload == 0 {
				c.State = StClosed
				c.Stages |= stgCLOSED
				lp.Note = "closed"
				lp.Explain = who + " acknowledges the last FIN — the connection is fully CLOSED"
			}
		}
	}

	if lp.Retrans {
		c.Retrans++
		lp.Kind, lp.Short, lp.Note = KRetrans, "RETX", "retransmission"
		lp.Explain = who + " re-sends a segment that was never acknowledged — a sign of packet loss or delay"
	}
	if ev.Window == 0 && !isRst {
		lp.Note = joinNote(lp.Note, "zero window")
		lp.Explain += ". Its receive window is 0: its buffer is full, so the other side must pause"
	}
	lp.Info = fmt.Sprintf("seq=%d ack=%d win=%d len=%d", lp.RelSeq, lp.RelAck, ev.Window, ev.Payload)
	if ev.Info != "" {
		lp.Info += "  " + ev.Info
	}
}

func (c *Conn) handleUDP(ev *PacketEvent, dir int, lp *LoggedPacket, who string) {
	other := 1 - dir
	c.State = StActive
	lp.Kind, lp.Short = KUDP, "UDP"
	if ev.App != "" {
		lp.Short = ev.App
	}
	// A datagram right after one from the other side looks like a response.
	if !c.lastSent[other].IsZero() && c.lastSent[other].After(c.lastSent[dir]) {
		c.RTT = ev.Time.Sub(c.lastSent[other])
		lp.Note = "reply after " + fmtDur(c.RTT)
	}
	c.lastSent[dir] = ev.Time
	lp.Explain = fmt.Sprintf("%s sends a %s UDP datagram (fire-and-forget: no handshake, no delivery guarantee)", who, humanBytes(ev.Payload))
	if ev.Info != "" {
		lp.Explain += " — " + ev.Info
	}
	lp.Info = fmt.Sprintf("len=%d ttl=%d", ev.Payload, ev.TTL)
	if ev.Info != "" {
		lp.Info += "  " + ev.Info
	}
}

func (c *Conn) handleICMP(ev *PacketEvent, dir int, lp *LoggedPacket, who string) {
	c.State = StActive
	lp.Kind, lp.Short = KICMP, "ICMP"
	key := uint32(ev.ICMPID)<<16 | uint32(ev.ICMPSeq)
	if c.echo == nil || len(c.echo) > 64 {
		c.echo = map[uint32]time.Time{}
	}
	switch {
	case isEchoReq(ev):
		lp.Short = "PING"
		c.echo[key] = ev.Time
		lp.Explain = fmt.Sprintf("%s sends a ping (ICMP echo request #%d) — \"are you there?\"", who, ev.ICMPSeq)
	case isEchoReply(ev):
		lp.Short = "PONG"
		if t0, ok := c.echo[key]; ok {
			c.RTT = ev.Time.Sub(t0)
			delete(c.echo, key)
			lp.Note = "RTT " + fmtDur(c.RTT)
		}
		lp.Explain = fmt.Sprintf("%s answers the ping (echo reply #%d) — the host is reachable", who, ev.ICMPSeq)
	case isICMPError(ev):
		lp.Kind, lp.Short = KICMPErr, "ICMP!"
		lp.Note = ev.Info
		lp.Explain = fmt.Sprintf("%s reports an error: %s — an earlier packet could not be delivered", who, ev.Info)
	default:
		lp.Explain = fmt.Sprintf("%s sends ICMP %s", who, ev.Info)
	}
	lp.Info = fmt.Sprintf("%s id=%d seq=%d ttl=%d", ev.Info, ev.ICMPID, ev.ICMPSeq, ev.TTL)
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + ", " + b
}

func fmtDur(d time.Duration) string {
	switch {
	case d < 0:
		return "0"
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	case d < time.Minute:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}

func humanBytes(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%dB", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1fMB", float64(n)/(1024*1024))
	}
	return fmt.Sprintf("%.2fGB", float64(n)/(1024*1024*1024))
}

func humanCount(n int) string {
	switch {
	case n < 1000:
		return strconv.Itoa(n)
	case n < 1_000_000:
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
}
