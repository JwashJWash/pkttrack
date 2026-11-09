# pkttrack

A terminal UI for watching packets to and from specific IPs and ports and seeing what each one is doing.

```
╭─ Flow · 1.1.1.1:443 ─────────────────────────────────────────────────────╮
│ 15 pkts   1.2KB   ▶ 9   ◀ 6   2 flows   last packet just now               │
│ to target   ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁█    4/s       │
│ from target ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▅    2/s       │
│ ╭────────╮                                                  ╭────────╮ │
│ │  YOU   │┄┄┄┄SYN▶┄┄┄┄┄┄┄┄┄┄┄TLS▶┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│ TARGET │ │
│ │  tx 9  │┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄◀SYN+ACK┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│  tx 6  │ │
│ ╰────────╯                                                  ╰────────╯ │
╰──────────────────────────────────────────────────────────────────────────╯
╭─ Flows ──────────────────────────────────────────────────────────────────╮
│ 192.168.1.42:53904  TCP  ESTABLISHED  ●SYN─●SYN/ACK─●ACK─●DATA─○FIN─○DONE  │
╰──────────────────────────────────────────────────────────────────────────╯
╭─ Packets ────────────────────────────────────────────────────────────────╮
│ 17:11:29.488          192.168.1.42:53904 ── SYN ─────────▶ :443          │
│ 17:11:29.519 +30.2ms  192.168.1.42:53904 ◀───── SYN,ACK ── :443 [RTT 30ms]│
│ 17:11:29.547 +28.8ms  192.168.1.42:53904 ── ACK ─────────▶ :443 [handshake]│
╰──────────────────────────────────────────────────────────────────────────╯
```

## What you see

- **Animated wire.** Each packet moves as a coloured token between the PEER (or YOU) box and the TARGET box. The box lights up when the packet arrives. Outbound packets use the top lane and inbound packets the bottom one.
- **Rate sparklines.** Packets per second to and from the target over the last couple of minutes.
- **Flow table.** Each connection is followed through its lifecycle: `SYN → SYN/ACK → ACK → DATA → FIN → DONE`. It shows the state (ESTABLISHED, FIN_WAIT, REFUSED, RESET…), the handshake RTT and retransmission counts.
- **Packet ladder.** A sequence diagram of every packet, with relative seq/ack numbers, deltas and highlights such as `[RTT]`, `[retransmission]`, `[connection refused]` and `[zero window]`. Press `v` to switch the details column to plain English, e.g. *"Target refused the connection — nothing is listening on that port"*.
- **Inspector.** Press `enter` on a packet to see each layer (Ethernet, IP, TCP options, DNS records…) and a hex dump. Use `←/→` to step through packets.
- **App-layer hints.** It recognises TLS ClientHello (including the SNI hostname), ServerHello and app data, HTTP request and status lines, SSH banners, DNS queries and answers, QUIC, NTP and DHCP.

## Build

Requires Go 1.22+ and libpcap. libpcap ships with macOS; on Linux run `apt install libpcap-dev`.

```bash
go build -o pkttrack .
```

## Run

To try it without root, using simulated traffic:

```bash
./pkttrack -demo
```

Live capture needs root, because it reads `/dev/bpf*` on macOS:

```bash
sudo ./pkttrack -t "1.1.1.1:443" -t "8.8.8.8:53 udp"
```

| Flag | Meaning |
|---|---|
| `-t target` | Add a target. Repeatable. |
| `-i en0` · `-i en0,lo0` · `-i all` | Interface(s) to capture on for this run. Defaults to the last selection you made in the app, or else the interface with the default route. |
| `-list` | List the interfaces you can capture on. `*` marks the default and `+` marks the ones `-i all` would pick. |
| `-config path` | Where targets are saved. Default: `~/.config/pkttrack/targets.txt`. Pass `""` to disable. |
| `-promisc` | Turn on promiscuous mode. |
| `-demo` | Use simulated traffic. In this mode your saved targets are not overwritten. |

## Adding targets

Press **`a`**. The form has a Host field, a Ports field and a Protocol picker (`←/→`). You can also type everything into the Host field, for example `8.8.8.8:53 udp`.

| Input | Meaning |
|---|---|
| `1.1.1.1:443` | One host, one port |
| `10.0.0.5:22,80,8000-8100` | Port lists and ranges |
| `192.168.1.0/24` | A whole subnet, any port |
| `[2001:db8::1]:443 tcp` | IPv6 |
| `github.com:https` | Hostnames (resolved to all their IPs) and service names |
| `8.8.8.8 icmp` | Pings and ICMP errors only |

Targets are compiled into a kernel BPF filter, so only matching packets leave the kernel. The filter is updated live whenever you add, edit, pause or delete a target. Your target list is saved automatically.

## Choosing interfaces

Press **`i`** to open the interface picker. It lists every capture interface with its friendly name (Wi-Fi, loopback, VPN / tunnel, Thunderbolt…), its state, its addresses and how many packets it has captured so far.

| Key | Action |
|---|---|
| `↑/↓` + `space` | Toggle individual interfaces, so you can pick one or several |
| `a` | All active interfaces: up, with a real (non-link-local) address, plus loopback. This choice is remembered as "all", so it adapts next time, e.g. when a VPN connects. |
| `A` | Every interface listed, including inactive ones |
| `d` | Just the default-route interface |
| `n` | Clear the selection |
| `enter` | Apply |

Changes take effect live. Interfaces you keep keep capturing, new ones start, and removed ones stop. If an interface can't be opened, it's reported and the rest still run. Packets from all selected interfaces are merged. When more than one interface is selected, the packet list gains an **IF** column showing where each packet was seen. If the same packet shows up on two interfaces (for example a bridge and its member port), it's counted only once.

Your selection is saved in the targets file as an `@interfaces …` line. A one-off `-i` on the command line overrides it for that run without changing what's saved. If the saved interfaces no longer exist (VPN down, adapter unplugged), pkttrack falls back to the default interface and tells you.

## Sending test packets

pkttrack can also create the traffic you're watching. Select a target and press **`t`** to open the *Send test packets* dialog:

| Field | Meaning |
|---|---|
| **Address** | The IP or hostname to send to. It's prefilled from the target: the target's IP, the first usable host of a CIDR range, or the IPv4 address of a hostname. You can type any address. If it's outside the target, the probe is still sent, but you'll be warned that its packets won't appear under that target. |
| **Port** | Destination port. Leave it blank to ping. |
| **Method** | `auto` (no port → ping, 53/123 → UDP, otherwise TCP), `tcp`, `udp` or `icmp`. |
| **Count** | How many probes to send, one per second. |
| **Payload** | Optional text to send over TCP/UDP. `\n`, `\r` and `\t` are allowed. |

What each method actually does:

- **tcp**: completes a real three-way handshake. On TLS ports (443, 8443, 993…) it then does a TLS handshake with SNI. On HTTP ports (80, 8080…) it sends `HEAD /`. On other ports it waits briefly for a banner (SSH, SMTP…). A closed port reports **refused**, and a firewalled one reports **no answer**.
- **udp**: sends a DNS query on 53, an NTP request on 123, and otherwise your payload or `pkttrack probe`. It reports the reply, an ICMP *port unreachable*, or silence (open or filtered).
- **icmp**: sends an echo request (ping) and reports the RTT, *unreachable* or a timeout.

The result appears on the `probe ▸` line in the Flow box, for example `✔ #1/1 tcp 1.1.1.1:443 → port open — handshake done in 6.9ms · TLS 1.3 handshake ok`. Your probe's own packets are tagged **⚑probe** in the packet list.

`T` re-sends the last probe for that target immediately (or the default probe if you haven't sent one), and `s` stops a probe that's running. Probes can run without root, but you only see the resulting packets in live mode when pkttrack is running with `sudo`. To probe a target on `127.0.0.1`, capture on loopback with `-i lo0`. In `-demo` mode, probes are simulated and nothing is sent on the network.

## Keys

| Key | Action |
|---|---|
| `a` / `e` / `d` / `u` | Add / edit / delete / undo delete |
| `t` / `T` / `s` | Send test packets / re-send the last probe / stop probing |
| `i` | Choose capture interfaces |
| `space` | Pause or resume the selected target |
| `c` | Clear its stats |
| `tab` | Switch focus between the targets list and the packet list |
| `↑↓` `pgup` `pgdn` | Move |
| `enter` | Inspect the selected packet |
| `f` / `G` | Follow the newest packets |
| `v` | Turn plain-English explanations on or off |
| `p` | Freeze the display |
| `?` | Help |
| `q` | Quit |

## Layout

| File | Contents |
|---|---|
| `targets.go` | Target parsing, matching, BPF generation, persistence |
| `capture.go` | libpcap capture (one reader per interface, switchable live), interface discovery, cross-interface dedupe |
| `iface_ui.go` | Interface picker |
| `decode.go` | Packet decoding, TLS/HTTP/DNS/QUIC sniffing, inspector |
| `tracker.go` | Per-flow TCP state machine, RTT, retransmissions, rates |
| `ui.go` | Bubble Tea UI |
| `probe.go`, `probe_ui.go` | Test-packet sender (TCP/TLS/HTTP, UDP/DNS/NTP, ICMP) and its dialog |
| `demo.go` | Traffic simulator. It serialises real packets and runs them through the same decoder. |
