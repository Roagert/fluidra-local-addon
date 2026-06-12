#!/usr/bin/env python3
"""emulator_flows.py - what did the app actually talk to?

Feed it a full packet capture from the Android emulator's built-in tap:
    emulator -avd NAME -writable-system -tcpdump toggle.cap

It needs no decryption. It answers: which remote endpoints (host-by-IP, port,
protocol) did the app contact, when were new connections opened, and - the point
here - what traffic moved at the instant you toggled the equipment.

    python3 emulator_flows.py toggle.cap                 # peer + connection summary
    python3 emulator_flows.py toggle.cap --around 1717000000 --window 3
    python3 emulator_flows.py --selftest

It flags MQTT/TLS (the likely AWS-IoT control channel) and, prominently, ANY
traffic to the LAN device IP - which would mean local control after all.
"""
from __future__ import annotations
import argparse, struct, zlib  # noqa: F401 (zlib used in selftest builder)
from collections import Counter, defaultdict

# ---- pcap parsing (classic libpcap; EN10MB / SLL / SLL2 / RAW / NULL) -------
_MAGICS = {b"\xa1\xb2\xc3\xd4": (">", 1e6), b"\xd4\xc3\xb2\xa1": ("<", 1e6),
           b"\xa1\xb2\x3c\x4d": (">", 1e9), b"\x4d\x3c\xb2\xa1": ("<", 1e9)}

def _link(lt, d):
    if lt == 1:
        if len(d) < 14: return None
        et = int.from_bytes(d[12:14], "big"); off = 14
        while et == 0x8100 and len(d) >= off + 4:
            et = int.from_bytes(d[off+2:off+4], "big"); off += 4
        return et, d[off:]
    if lt == 113:
        return (int.from_bytes(d[14:16], "big"), d[16:]) if len(d) >= 16 else None
    if lt == 276:
        return (int.from_bytes(d[0:2], "big"), d[20:]) if len(d) >= 20 else None
    if lt == 101:
        return ((0x0800 if d and (d[0] >> 4) == 4 else 0x86DD), d) if d else None
    if lt == 0:
        if len(d) < 4: return None
        fam = int.from_bytes(d[0:4], "little")
        return (0x0800 if fam == 2 else 0x86DD, d[4:])
    return None

def _ipv4(d):
    if len(d) < 20 or (d[0] >> 4) != 4: return None
    ihl = (d[0] & 0x0F) * 4
    if ihl < 20 or len(d) < ihl: return None
    return d[9], ".".join(map(str, d[12:16])), ".".join(map(str, d[16:20])), d[ihl:]

def parse(raw):
    """Yield (ts, proto, src, sport, dst, dport, flags, payload_len)."""
    if raw[:4] not in _MAGICS:
        raise ValueError("not a classic pcap (convert pcapng: tcpdump -r in -w out)")
    en, div = _MAGICS[raw[:4]]
    lt = struct.unpack(en + "I", raw[20:24])[0]
    off, rec = 24, struct.Struct(en + "IIII")
    while off + 16 <= len(raw):
        ts_s, ts_f, incl, _ = rec.unpack(raw[off:off+16]); off += 16
        if off + incl > len(raw): break
        frame = raw[off:off+incl]; off += incl
        lk = _link(lt, frame)
        if not lk or lk[0] != 0x0800: continue
        ip = _ipv4(lk[1])
        if not ip: continue
        proto, src, dst, l4 = ip; ts = ts_s + ts_f / div
        if proto == 6 and len(l4) >= 20:
            sport = int.from_bytes(l4[0:2], "big"); dport = int.from_bytes(l4[2:4], "big")
            doff = (l4[12] >> 4) * 4
            yield ts, "TCP", src, sport, dst, dport, l4[13], max(0, len(l4) - doff)
        elif proto == 17 and len(l4) >= 8:
            sport = int.from_bytes(l4[0:2], "big"); dport = int.from_bytes(l4[2:4], "big")
            yield ts, "UDP", src, sport, dst, dport, 0, max(0, len(l4) - 8)

# ---- analysis ---------------------------------------------------------------
PORT_NOTE = {443: "TLS (HTTPS/WSS)", 80: "HTTP", 53: "DNS", 8883: "MQTT/TLS (AWS IoT)",
             1883: "MQTT", 8884: "MQTT/WSS", 853: "DoT"}

def _emu_side(ip):  # emulator NAT block
    return ip.startswith("10.0.2.")

def analyze(raw, device_ip="192.168.1.29", around=None, window=3.0, top=40):
    pkts = list(parse(raw))
    agg = defaultdict(lambda: {"pkts": 0, "bytes": 0, "first": None, "last": None})
    syns = []
    device_hits = []
    for ts, proto, src, sport, dst, dport, flags, plen in pkts:
        # remote = the non-emulator endpoint
        if not _emu_side(src):
            rip, rport = src, sport
        else:
            rip, rport = dst, dport
        k = (proto, rip, rport)
        a = agg[k]; a["pkts"] += 1; a["bytes"] += plen
        a["first"] = ts if a["first"] is None else min(a["first"], ts)
        a["last"] = ts if a["last"] is None else max(a["last"], ts)
        if proto == "TCP" and (flags & 0x12) == 0x02:  # SYN, not SYN-ACK
            syns.append((ts, src, dst, dport))
        if rip == device_ip:
            device_hits.append((ts, proto, src, sport, dst, dport, plen))

    out = []
    out.append("emulator flow summary")
    out.append("=" * 32)
    out.append(f"packets: {len(pkts)}   distinct remote endpoints: {len(agg)}")

    if device_hits:
        out.append("\n*** TRAFFIC TO/FROM LAN DEVICE %s DETECTED (%d pkts) ***" %
                   (device_ip, len(device_hits)))
        out.append("    this would indicate LOCAL control - investigate immediately:")
        for ts, proto, s, sp, d, dp, pl in device_hits[:20]:
            out.append(f"      {ts:.3f} {proto} {s}:{sp} -> {d}:{dp} len={pl}")
    else:
        out.append(f"\nno traffic to LAN device {device_ip} (consistent with cloud-only control)")

    rows = sorted(agg.items(), key=lambda kv: -kv[1]["bytes"])[:top]
    out.append("\nremote endpoints by bytes:")
    out.append(f"  {'proto':5} {'ip':<16} {'port':<6} {'pkts':>6} {'bytes':>9}  note")
    for (proto, ip, port), a in rows:
        note = PORT_NOTE.get(port, "")
        if ip == device_ip: note = "LAN DEVICE!"
        out.append(f"  {proto:5} {ip:<16} {port:<6} {a['pkts']:>6} {a['bytes']:>9}  {note}")

    if syns:
        out.append("\nnew TCP connections (chronological):")
        for ts, s, d, dp in syns[:40]:
            out.append(f"  {ts:.3f}  {s} -> {d}:{dp}  {PORT_NOTE.get(dp,'')}")

    if around is not None:
        lo, hi = around - window, around + window
        win = [p for p in pkts if lo <= p[0] <= hi]
        out.append(f"\npackets within {window}s of t={around} ({len(win)} pkts) - the toggle burst:")
        for ts, proto, s, sp, d, dp, fl, pl in win:
            remote = d if _emu_side(s) else s
            rp = dp if _emu_side(s) else sp
            out.append(f"  {ts-around:+.3f}s {proto} -> {remote}:{rp} len={pl} "
                       f"{PORT_NOTE.get(rp,'')}")
        if not win:
            out.append("  (none - widen --window, or the toggle used no network here)")
    return "\n".join(out)

# ---- selftest ---------------------------------------------------------------
def _w(pkts):
    import io
    b = io.BytesIO(); b.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, raw in pkts:
        s = int(ts); u = int(round((ts - s) * 1e6))
        b.write(struct.pack("<IIII", s, u, len(raw), len(raw)) + raw)
    return b.getvalue()

def _ip2b(s): return bytes(int(x) for x in s.split("."))
def _eth(): return b"\x11\x22\x33\x44\x55\x66\xaa\xbb\xcc\xdd\xee\xff\x08\x00"
def _udp(src, dst, sp, dp, pl=b""):
    u = struct.pack(">HHHH", sp, dp, 8 + len(pl), 0) + pl
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(u), 0, 0, 64, 17, 0) + _ip2b(src) + _ip2b(dst)
    return _eth() + ip + u
def _tcp(src, dst, sp, dp, flags, pl=b""):
    t = struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 0x50, flags, 0, 0, 0) + pl
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(t), 0, 0, 64, 6, 0) + _ip2b(src) + _ip2b(dst)
    return _eth() + ip + t

def selftest():
    ok = True
    def ck(n, c):
        nonlocal ok; print(f"  [{'PASS' if c else 'FAIL'}] {n}"); ok = ok and bool(c)
    G = "10.0.2.15"           # emulator guest
    T = 1000.0
    pk = []
    pk.append((T-5, _udp(G, "10.0.2.3", 40000, 53, b"\x00"*20)))             # DNS
    pk.append((T-4, _tcp(G, "52.1.2.3", 50000, 443, 0x02)))                  # SYN to cloud 443
    pk.append((T-3, _tcp("52.1.2.3", G, 443, 50000, 0x10, b"x"*100)))        # cloud data in
    pk.append((T-2, _tcp(G, "52.9.9.9", 50001, 8883, 0x02)))                 # SYN to MQTT 8883
    pk.append((T+0.2, _tcp(G, "52.9.9.9", 50001, 8883, 0x18, b"PUBLISH"*5))) # MQTT burst at toggle
    pk.append((T+0.3, _tcp("52.9.9.9", G, 8883, 50001, 0x18, b"PUBACK"*4)))  # MQTT ack
    raw = _w(pk)
    r = analyze(raw, device_ip="192.168.1.29", around=T, window=1.0)
    ck("no device traffic reported", "no traffic to LAN device" in r)
    ck("MQTT/TLS endpoint flagged", "MQTT/TLS (AWS IoT)" in r)
    ck("new TCP connections listed", "new TCP connections" in r)
    ck("toggle-window burst captured", "+0.200s" in r and "PUBLISH" not in r)  # content not printed, only len
    ck("8883 burst within window shown", "-> 52.9.9.9:8883" in r)

    # device-traffic case must trigger the LOCAL banner
    pk2 = [(T, _udp(G, "192.168.1.29", 51000, 9003, b"\xfa\xc2hello"))]
    r2 = analyze(_w(pk2), device_ip="192.168.1.29")
    ck("LAN device traffic raises local-control banner",
       "TRAFFIC TO/FROM LAN DEVICE" in r2 and "LOCAL control" in r2)
    print("\nSELFTEST", "PASS" if ok else "FAIL")
    print("\n--- example output (cloud/MQTT case) ---\n" + r)
    return 0 if ok else 1

def main(argv=None):
    ap = argparse.ArgumentParser(description="Summarize emulator packet capture by remote endpoint.")
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--device-ip", default="192.168.1.29")
    ap.add_argument("--around", type=float, help="epoch seconds of the toggle, to dump the burst")
    ap.add_argument("--window", type=float, default=3.0)
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest: return selftest()
    if not a.pcap: ap.error("give a pcap, or --selftest")
    with open(a.pcap, "rb") as f: raw = f.read()
    try:
        print(analyze(raw, a.device_ip, a.around, a.window, a.top))
    except ValueError as e:
        print("error:", e); return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
