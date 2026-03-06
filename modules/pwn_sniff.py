"""
pwn_sniff.py - PwnSniff: Passive Promiscuous DPI Sniffer for PagerPwn

Promiscuous mode packet sniffer with deep packet inspection. No ARP
poisoning, no MitM — just listens to everything on the wire passively.

Parses:
  - DNS queries + responses
  - HTTP GET/POST with Host, Auth, cookie headers
  - POST body credential extraction
  - TLS SNI (Server Name Indication) from ClientHello
  - Cleartext protocols: FTP, Telnet, SMTP, POP3, IMAP
  - DHCP discover/request/offer/ack (hostname + IP assignment)
  - mDNS / LLMNR name announcements
  - SMB session setup (NTLMSSP domain/user)
  - SSH version strings

Live color-coded LCD feed:
  GREEN   = credentials / auth
  CYAN    = DNS / mDNS / LLMNR
  YELLOW  = HTTP
  MAGENTA = TLS SNI
  WHITE   = DHCP / SMB / SSH
  GRAY    = info

Module interface: run(config, ui_callback, stop_event, pager=None) -> dict
"""

import os
import struct
import socket
import fcntl
import threading
import time
import queue
from datetime import datetime

from pagerctl import Pager

# ── Constants ────────────────────────────────────────────────────────────────

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914


# ── Network helpers ──────────────────────────────────────────────────────────

def _get_hw_addr(iface):
    """Get MAC address of interface via ioctl."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", iface.encode()[:15]))
        s.close()
        return info[18:24]
    except Exception:
        return b"\x00" * 6


def _mac_str(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _set_promisc(iface, enable=True):
    """Enable or disable promiscuous mode on an interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Get current flags
    ifreq = struct.pack("16sH14s", iface.encode()[:15], 0, b"\x00" * 14)
    result = fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, ifreq)
    flags = struct.unpack("16sH14s", result)[1]

    if enable:
        flags |= IFF_PROMISC
    else:
        flags &= ~IFF_PROMISC

    ifreq = struct.pack("16sH14s", iface.encode()[:15], flags, b"\x00" * 14)
    fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifreq)
    s.close()


# ── Packet parsing ───────────────────────────────────────────────────────────

def _parse_dns(data, src_ip, dst_ip, dst_port, feed_queue):
    """Extract DNS query/response names."""
    if len(data) < 12:
        return
    flags = struct.unpack(">H", data[2:4])[0]
    is_response = (flags >> 15) & 1

    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length >= 0xC0:
            offset += 2
            break
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(labels) if labels else ""
    if not name:
        return

    if is_response:
        feed_queue.put(("dns", f"DNS> {name}", Pager.CYAN))
    else:
        feed_queue.put(("dns", f"DNS? {name}", Pager.CYAN))


def _parse_mdns_llmnr(data, src_ip, port, feed_queue):
    """Parse mDNS (5353) and LLMNR (5355) announcements."""
    if len(data) < 12:
        return
    flags = struct.unpack(">H", data[2:4])[0]
    is_response = (flags >> 15) & 1

    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            break
        if length >= 0xC0:
            break
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(labels) if labels else ""
    if not name:
        return

    proto = "mDNS" if port == 5353 else "LLMNR"
    direction = ">" if is_response else "?"
    feed_queue.put(("dns", f"{proto}{direction} {name} ({src_ip})", Pager.CYAN))


def _parse_http(data, src_ip, dst_ip, src_port, dst_port, feed_queue):
    """Extract HTTP method, host, auth headers, POST bodies."""
    try:
        text = data[:2048].decode("ascii", errors="replace")
    except Exception:
        return

    lines = text.split("\r\n")
    if not lines:
        return

    first = lines[0]

    if any(first.startswith(m) for m in ("GET ", "POST ", "PUT ", "HEAD ", "DELETE ")):
        host = ""
        auth = ""
        cookie = ""
        for line in lines[1:]:
            low = line.lower()
            if low.startswith("host:"):
                host = line.split(":", 1)[1].strip()
            elif low.startswith("authorization:"):
                auth = line.split(":", 1)[1].strip()
            elif low.startswith("cookie:"):
                cookie = line.split(":", 1)[1].strip()

        method_path = first.split(" ")[0:2]
        method = method_path[0] if method_path else "?"
        path = method_path[1] if len(method_path) > 1 else "/"
        if len(path) > 30:
            path = path[:29] + "~"

        feed_queue.put(("http", f"{src_ip} {method} {host}{path}", Pager.YELLOW))

        if auth:
            feed_queue.put(("cred", f"AUTH: {auth[:50]}", Pager.GREEN))

        if cookie and len(cookie) > 10:
            feed_queue.put(("http", f"COOKIE: {cookie[:45]}", Pager.YELLOW))

        if method == "POST" and "\r\n\r\n" in text:
            body = text.split("\r\n\r\n", 1)[1][:200]
            if body:
                low_body = body.lower()
                if any(k in low_body for k in ("pass", "user", "login", "email", "token")):
                    feed_queue.put(("cred", f"POST: {body[:50]}", Pager.GREEN))


def _parse_tls_sni(data, src_ip, feed_queue):
    """Extract SNI from TLS ClientHello."""
    # TLS record: type=22 (handshake), then version, length
    if len(data) < 11:
        return
    if data[0] != 0x16:  # not handshake
        return
    # Handshake type: ClientHello = 1
    if data[5] != 0x01:
        return

    # Skip: record header (5) + handshake header (4) + client_version (2) + random (32)
    pos = 5 + 4 + 2 + 32
    if pos + 1 > len(data):
        return
    # Session ID length
    sid_len = data[pos]
    pos += 1 + sid_len
    if pos + 2 > len(data):
        return
    # Cipher suites length
    cs_len = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2 + cs_len
    if pos + 1 > len(data):
        return
    # Compression methods length
    cm_len = data[pos]
    pos += 1 + cm_len
    if pos + 2 > len(data):
        return
    # Extensions length
    ext_len = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    ext_end = pos + ext_len

    while pos + 4 <= ext_end and pos + 4 <= len(data):
        ext_type = struct.unpack(">H", data[pos:pos + 2])[0]
        ext_data_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        pos += 4
        if ext_type == 0x0000:  # SNI extension
            if pos + 5 <= len(data):
                # SNI list length (2) + type (1) + name length (2)
                name_len = struct.unpack(">H", data[pos + 3:pos + 5])[0]
                if pos + 5 + name_len <= len(data):
                    sni = data[pos + 5:pos + 5 + name_len].decode("ascii", errors="replace")
                    feed_queue.put(("tls", f"TLS> {src_ip} -> {sni}", Pager.MAGENTA))
            return
        pos += ext_data_len


def _parse_cleartext(data, src_ip, dst_port, feed_queue):
    """Parse FTP/Telnet/SMTP/POP3/IMAP cleartext creds."""
    try:
        text = data[:512].decode("ascii", errors="replace").strip()
    except Exception:
        return
    if not text:
        return

    proto_map = {21: "FTP", 23: "TELNET", 25: "SMTP", 110: "POP3", 143: "IMAP"}
    proto = proto_map.get(dst_port, "CLEAR")

    low = text.lower()
    if any(k in low for k in ("user", "pass", "login", "auth")):
        feed_queue.put(("cred", f"{proto}: {text[:50]}", Pager.GREEN))


def _parse_dhcp(data, src_ip, feed_queue):
    """Parse DHCP discover/offer/request/ack for hostname + IP."""
    if len(data) < 240:
        return

    op = data[0]  # 1=request, 2=reply
    yiaddr = socket.inet_ntoa(data[16:20])
    chaddr = _mac_str(data[28:34])

    # Check magic cookie
    if data[236:240] != b"\x63\x82\x53\x63":
        return

    # Parse options
    hostname = ""
    msg_type = 0
    pos = 240
    while pos < len(data):
        opt = data[pos]
        if opt == 255:  # end
            break
        if opt == 0:  # padding
            pos += 1
            continue
        if pos + 1 >= len(data):
            break
        opt_len = data[pos + 1]
        pos += 2
        if pos + opt_len > len(data):
            break
        if opt == 53 and opt_len == 1:  # DHCP message type
            msg_type = data[pos]
        elif opt == 12:  # hostname
            hostname = data[pos:pos + opt_len].decode("ascii", errors="replace")
        pos += opt_len

    type_names = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK"}
    type_str = type_names.get(msg_type, f"TYPE{msg_type}")

    info = f"DHCP {type_str}"
    if hostname:
        info += f" [{hostname}]"
    if yiaddr != "0.0.0.0":
        info += f" {yiaddr}"
    info += f" ({chaddr})"

    feed_queue.put(("dhcp", info, Pager.WHITE))


def _parse_smb(data, src_ip, feed_queue):
    """Look for NTLMSSP domain/user in SMB session setup."""
    try:
        idx = data.find(b"NTLMSSP\x00")
        if idx < 0:
            return
        msg_type = struct.unpack("<I", data[idx + 8:idx + 12])[0]
        if msg_type == 3:  # Auth message
            # Domain offset/length at +28, User at +36
            domain_len = struct.unpack("<H", data[idx + 28:idx + 30])[0]
            domain_off = struct.unpack("<I", data[idx + 32:idx + 36])[0]
            user_len = struct.unpack("<H", data[idx + 36:idx + 38])[0]
            user_off = struct.unpack("<I", data[idx + 40:idx + 44])[0]

            domain = data[idx + domain_off:idx + domain_off + domain_len].decode("utf-16-le", errors="replace")
            user = data[idx + user_off:idx + user_off + user_len].decode("utf-16-le", errors="replace")

            if user:
                feed_queue.put(("cred", f"SMB: {domain}\\{user} ({src_ip})", Pager.GREEN))
    except Exception:
        pass


def _parse_ssh_version(data, src_ip, dst_port, feed_queue):
    """Capture SSH version strings."""
    try:
        text = data[:256].decode("ascii", errors="replace").strip()
    except Exception:
        return
    if text.startswith("SSH-"):
        feed_queue.put(("ssh", f"SSH: {src_ip} {text[:45]}", Pager.WHITE))


# ── Sniffer thread ───────────────────────────────────────────────────────────

def _sniffer_loop(iface, our_ip, stop_event, feed_queue, stats):
    """Promiscuous raw socket sniffer with DPI."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((iface, 0))
        sock.settimeout(0.5)
    except Exception as e:
        feed_queue.put(("info", f"Socket error: {e}", Pager.RED))
        return

    while not stop_event.is_set():
        try:
            data = sock.recv(65535)
        except socket.timeout:
            continue
        except Exception:
            break

        if len(data) < 14:
            continue

        stats["packets"] += 1

        # Ethernet header
        eth_type = struct.unpack(">H", data[12:14])[0]

        if eth_type != ETH_P_IP:
            continue

        ip_header = data[14:]
        if len(ip_header) < 20:
            continue

        ihl = (ip_header[0] & 0x0F) * 4
        total_len = struct.unpack(">H", ip_header[2:4])[0]
        ip_packet = ip_header[:total_len]
        proto = ip_packet[9]
        src_ip = socket.inet_ntoa(ip_packet[12:16])
        dst_ip = socket.inet_ntoa(ip_packet[16:20])

        payload = ip_packet[ihl:]

        # UDP
        if proto == 17 and len(payload) >= 8:
            src_port = struct.unpack(">H", payload[0:2])[0]
            dst_port = struct.unpack(">H", payload[2:4])[0]
            udp_data = payload[8:]

            # DNS
            if dst_port == 53 or src_port == 53:
                _parse_dns(udp_data, src_ip, dst_ip, dst_port, feed_queue)

            # mDNS / LLMNR
            elif dst_port in (5353, 5355) or src_port in (5353, 5355):
                port = dst_port if dst_port in (5353, 5355) else src_port
                _parse_mdns_llmnr(udp_data, src_ip, port, feed_queue)

            # DHCP
            elif dst_port in (67, 68) or src_port in (67, 68):
                _parse_dhcp(udp_data, src_ip, feed_queue)

        # TCP
        elif proto == 6 and len(payload) >= 20:
            src_port = struct.unpack(">H", payload[0:2])[0]
            dst_port = struct.unpack(">H", payload[2:4])[0]
            tcp_hdr_len = ((payload[12] >> 4) & 0x0F) * 4
            tcp_data = payload[tcp_hdr_len:]

            if not tcp_data:
                continue

            # HTTP
            if dst_port == 80 or src_port == 80:
                _parse_http(tcp_data, src_ip, dst_ip, src_port, dst_port, feed_queue)

            # TLS SNI
            elif dst_port == 443 or dst_port == 8443:
                _parse_tls_sni(tcp_data, src_ip, feed_queue)

            # SSH version
            elif dst_port == 22 or src_port == 22:
                _parse_ssh_version(tcp_data, src_ip, dst_port, feed_queue)

            # SMB
            elif dst_port == 445 or src_port == 445:
                _parse_smb(tcp_data, src_ip, feed_queue)

            # Cleartext cred protocols
            if dst_port in (21, 23, 25, 110, 143) or src_port in (21, 23, 25, 110, 143):
                _parse_cleartext(tcp_data, src_ip, dst_port, feed_queue)

    sock.close()


# ── LCD drawing ──────────────────────────────────────────────────────────────

def _draw_launch_screen(pager, iface):
    """Draw launch/description screen."""
    pager.clear(Pager.BLACK)
    pager.fill_rect(0, 0, 480, 22, Pager.rgb(0, 120, 180))
    pager.draw_text(6, 3, "PWNSNIFF", Pager.WHITE, 2)

    pager.draw_text_centered(35, "Promiscuous Sniffer", Pager.CYAN, 2)
    pager.draw_text_centered(65, "Passive DPI - no MitM required", Pager.GRAY, 2)
    pager.draw_text_centered(90, f"Interface: {iface}", Pager.WHITE, 2)

    y = 120
    for line, color in [
        ("DNS / mDNS / LLMNR", Pager.CYAN),
        ("HTTP / TLS SNI / Creds", Pager.YELLOW),
        ("DHCP / SMB / SSH", Pager.WHITE),
    ]:
        pager.draw_text(80, y, line, color, 1)
        y += 14

    pager.draw_text_centered(185, "[A] START  [B] BACK", Pager.GREEN, 2)
    pager.flip()


def _draw_sniff_screen(pager, iface, feed_lines, scroll_offset, elapsed, pkt_count):
    """Draw live sniff feed."""
    pager.clear(Pager.BLACK)

    # Header
    pager.fill_rect(0, 0, 480, 20, Pager.rgb(0, 120, 180))
    mins, secs = divmod(elapsed, 60)
    pager.draw_text(4, 2, f"PWNSNIFF  {iface}", Pager.WHITE, 2)

    # Feed area
    LINE_H = 11
    MAX_LINES = 15
    y = 22

    visible = feed_lines[scroll_offset:scroll_offset + MAX_LINES]
    for text, color in visible:
        pager.draw_text(4, y, text[:56], color, 1)
        y += LINE_H

    # Status bar
    pager.fill_rect(0, 204, 480, 18, Pager.rgb(40, 40, 40))
    total = len(feed_lines)
    end = min(scroll_offset + MAX_LINES, total)
    pager.draw_text(4, 206,
                    f"PKT:{pkt_count}  {mins:02d}:{secs:02d}  [{end}/{total}]  [B] STOP",
                    Pager.GRAY, 1)
    pager.flip()


# ── Main entry point ─────────────────────────────────────────────────────────

def run(config, ui_callback, stop_event, pager=None):
    """
    PwnSniff: passive promiscuous DPI sniffer.

    Args:
        config: PagerPwn config dict (needs IFACE)
        ui_callback: function(line1, line2)
        stop_event: threading.Event
        pager: Pager object for LCD

    Returns:
        dict with sniff results
    """
    if pager is None:
        ui_callback("[PWNSNIFF]", "No pager ref")
        time.sleep(2)
        return {"error": "no_pager"}

    iface = config.get("IFACE", "eth0")

    # ── Launch screen ────────────────────────────────────────────────────
    pager.clear_input_events()
    _draw_launch_screen(pager, iface)

    while not (stop_event and stop_event.is_set()):
        event = pager.get_input_event()
        if not event:
            time.sleep(0.02)
            continue
        btn, etype, _ = event
        if etype != Pager.EVENT_PRESS:
            continue
        if btn == Pager.BTN_A:
            pager.beep(800, 40)
            break
        elif btn == Pager.BTN_B:
            pager.beep(300, 30)
            return {"aborted": True}

    # ── Enable promiscuous mode ──────────────────────────────────────────
    promisc_set = False
    try:
        _set_promisc(iface, True)
        promisc_set = True
    except Exception as e:
        pager.clear(Pager.BLACK)
        pager.draw_text_centered(80, "PROMISC MODE FAILED", Pager.RED, 2)
        pager.draw_text_centered(110, str(e)[:40], Pager.GRAY, 1)
        pager.draw_text_centered(150, "Continuing in normal mode", Pager.YELLOW, 2)
        pager.flip()
        time.sleep(2)

    # ── Start sniffer thread ─────────────────────────────────────────────
    sniff_stop = threading.Event()
    feed_queue = queue.Queue()
    feed_lines = []
    stats = {"packets": 0}

    our_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", iface.encode()[:15]))
        s.close()
        our_ip = socket.inet_ntoa(info[20:24])
    except Exception:
        pass

    sniffer_t = threading.Thread(
        target=_sniffer_loop,
        args=(iface, our_ip, sniff_stop, feed_queue, stats),
        daemon=True,
    )
    sniffer_t.start()

    feed_queue.put(("info", f"Sniffing on {iface} (promisc={'ON' if promisc_set else 'OFF'})", Pager.GRAY))
    if our_ip:
        feed_queue.put(("info", f"Our IP: {our_ip}", Pager.GRAY))

    # Blue LED
    try:
        pager.led_set("b-button-led", 255)
    except Exception:
        pass

    start_time = time.time()
    scroll_offset = 0
    auto_scroll = True
    pager.clear_input_events()

    MAX_FEED = 500

    # ── Live display loop ────────────────────────────────────────────────
    while not (stop_event and stop_event.is_set()):
        # Check buttons FIRST for responsiveness
        while True:
            event = pager.get_input_event()
            if not event:
                break
            btn, etype, _ = event
            if etype != Pager.EVENT_PRESS:
                continue
            if btn == Pager.BTN_B:
                pager.beep(200, 100)
                sniff_stop.set()
                pager.clear_input_events()
                break
            elif btn == Pager.BTN_UP:
                scroll_offset = max(0, scroll_offset - 1)
                auto_scroll = False
            elif btn == Pager.BTN_DOWN:
                max_off = max(0, len(feed_lines) - 15)
                scroll_offset = min(scroll_offset + 1, max_off)
                if scroll_offset >= max_off:
                    auto_scroll = True
            elif btn == Pager.BTN_LEFT:
                scroll_offset = max(0, scroll_offset - 15)
                auto_scroll = False
            elif btn == Pager.BTN_RIGHT:
                max_off = max(0, len(feed_lines) - 15)
                scroll_offset = min(scroll_offset + 15, max_off)
                if scroll_offset >= max_off:
                    auto_scroll = True

        if sniff_stop.is_set():
            break

        # Drain feed queue (max 20 per frame)
        drained = 0
        while drained < 20:
            try:
                item = feed_queue.get_nowait()
                feed_lines.append((item[1], item[2]))
                drained += 1
            except Exception:
                break

        if len(feed_lines) > MAX_FEED:
            feed_lines = feed_lines[-MAX_FEED:]

        if auto_scroll:
            max_off = max(0, len(feed_lines) - 15)
            scroll_offset = max_off

        elapsed = int(time.time() - start_time)
        _draw_sniff_screen(pager, iface, feed_lines, scroll_offset,
                           elapsed, stats["packets"])

        time.sleep(0.1)

    # ── Cleanup ──────────────────────────────────────────────────────────
    sniff_stop.set()

    if stop_event:
        stop_event.set()

    # Disable promiscuous mode
    if promisc_set:
        try:
            _set_promisc(iface, False)
        except Exception:
            pass

    # LED off
    try:
        pager.led_set("b-button-led", 0)
    except Exception:
        pass

    sniffer_t.join(timeout=0.5)

    duration = int(time.time() - start_time)

    # Count creds
    creds = [text for text, color in feed_lines if color == Pager.GREEN]

    # ── Result screen ────────────────────────────────────────────────────
    pager.clear(Pager.BLACK)
    pager.fill_rect(0, 0, 480, 22, Pager.rgb(0, 120, 180))
    pager.draw_text(6, 3, "SNIFF COMPLETE", Pager.WHITE, 2)
    pager.draw_text_centered(50, f"Packets: {stats['packets']}", Pager.CYAN, 2)
    pager.draw_text_centered(80, f"Events: {len(feed_lines)}", Pager.WHITE, 2)
    pager.draw_text_centered(110, f"Creds/Auth: {len(creds)}", Pager.GREEN, 2)
    pager.draw_text_centered(140, f"Duration: {duration}s", Pager.GRAY, 2)
    pager.draw_text_centered(180, "[A] CONTINUE", Pager.GREEN, 2)
    pager.flip()

    pager.clear_input_events()
    while True:
        event = pager.get_input_event()
        if event:
            btn, etype, _ = event
            if btn == Pager.BTN_A and etype == Pager.EVENT_PRESS:
                break
        time.sleep(0.03)

    # ── Save loot ────────────────────────────────────────────────────────
    loot_dir = config.get("LOOT_DIR", "/mmc/root/loot/pagerpwn")
    os.makedirs(loot_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    loot_text = [
        "PWNSNIFF REPORT",
        "================",
        f"Date:       {datetime.now().isoformat()}",
        f"Duration:   {duration}s",
        f"Interface:  {iface}",
        f"Packets:    {stats['packets']}",
        f"Events:     {len(feed_lines)}",
        f"Creds/Auth: {len(creds)}",
        "",
        "CAPTURED FEED",
        "=============",
    ]
    for text, color in feed_lines:
        loot_text.append(text)

    loot_path = os.path.join(loot_dir, f"pwnsniff_{ts}.txt")
    try:
        with open(loot_path, "w") as f:
            f.write("\n".join(loot_text) + "\n")
    except Exception:
        pass

    return {
        "packets": stats["packets"],
        "events": len(feed_lines),
        "creds": creds,
        "duration": duration,
        "loot_file": loot_path,
    }
