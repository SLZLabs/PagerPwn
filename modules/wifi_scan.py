"""
wifi_scan.py - Passive WiFi Scanner for PagerPwn

Sniffs 802.11 Beacon, Probe Request, and Probe Response frames via a
monitor-mode interface. Hops channels across 2.4GHz (1-11).

When pineapplepager is stopped the firmware-managed monitor interfaces
(wlan0mon/wlan1mon) disappear. This module creates its own monitor
interface (ppwn0mon) on phy0 at startup and tears it down on exit.
If an existing monitor iface is already present, it uses that instead.

phy0 = 2.4GHz only (supports monitor mode)
phy1 = dual-band but does NOT expose monitor mode to userspace

Uses AF_PACKET raw socket — no external dependencies.

Module interface: run(config, ui_callback, stop_event, pager=None) -> dict
"""

import os
import struct
import socket
import subprocess
import threading
import time
from datetime import datetime

# ── Channel lists ────────────────────────────────────────────────────────────
CHANNELS_24 = list(range(1, 12))                     # 1-11
# phy0 is 2.4GHz only — no 5GHz channels available when self-managed
ALL_CHANNELS = CHANNELS_24
HOP_INTERVAL = 1.5  # seconds between hops

# ── 802.11 frame subtypes (from frame control field) ─────────────────────────
SUBTYPE_BEACON     = 0x80
SUBTYPE_PROBE_RESP = 0x50
SUBTYPE_PROBE_REQ  = 0x40

# ── Encryption tag IDs ───────────────────────────────────────────────────────
IE_SSID = 0
IE_DS_PARAM = 3          # DS Parameter Set (channel)
IE_RSN  = 48             # RSN (WPA2)
IE_VENDOR = 221           # Vendor-specific (WPA1 lives here)
WPA_OUI = b"\x00\x50\xf2\x01"

MON_IFACE = "ppwn0mon"    # our self-managed monitor interface
MON_PHY   = "phy0"        # 2.4GHz radio that supports monitor mode

# Absolute paths — payload runner may have a stripped PATH
IW  = "/usr/sbin/iw"
IP  = "/sbin/ip"


# ── Monitor interface management ─────────────────────────────────────────────

def _find_existing_mon():
    """Check if any monitor interface already exists. Returns name or None."""
    for candidate in ("wlan1mon", "wlan0mon", MON_IFACE):
        try:
            out = subprocess.check_output(
                [IW, "dev", candidate, "info"],
                stderr=subprocess.DEVNULL, timeout=3,
            ).decode()
            if "monitor" in out:
                return candidate
        except Exception:
            continue
    return None


def _create_mon_iface():
    """Create a monitor interface on phy0. Returns iface name or None."""
    try:
        subprocess.run(
            [IW, "phy", MON_PHY, "interface", "add", MON_IFACE, "type", "monitor"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=True,
        )
        subprocess.run(
            [IP, "link", "set", MON_IFACE, "up"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=3, check=True,
        )
        return MON_IFACE
    except Exception:
        return None


def _destroy_mon_iface(iface):
    """Remove our self-created monitor interface."""
    if iface != MON_IFACE:
        return  # don't destroy interfaces we didn't create
    try:
        subprocess.run(
            [IP, "link", "set", iface, "down"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3,
        )
        subprocess.run(
            [IW, "dev", iface, "del"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3,
        )
    except Exception:
        pass


# ── Radiotap + 802.11 parsing ────────────────────────────────────────────────

def _parse_radiotap(data):
    """Extract radiotap header length and signal strength (dBm).
    Returns (header_len, signal_dbm) or (None, None) on failure."""
    if len(data) < 8:
        return None, None
    # Radiotap: version(1) + pad(1) + length(2) + present_flags(4)
    _ver, _pad, rt_len, present = struct.unpack_from("<BBHI", data, 0)
    if rt_len > len(data):
        return None, None

    signal = None
    # Bit 5 in present flags = dBm Antenna Signal
    if present & (1 << 5):
        # Walk through present fields to find signal offset
        offset = 8
        # Skip fields before signal (bits 0-4)
        # Bit 0: TSFT (8 bytes, aligned to 8)
        if present & (1 << 0):
            # Align to 8
            offset = (offset + 7) & ~7
            offset += 8
        # Bit 1: Flags (1 byte)
        if present & (1 << 1):
            offset += 1
        # Bit 2: Rate (1 byte)
        if present & (1 << 2):
            offset += 1
        # Bit 3: Channel (4 bytes, aligned to 2)
        if present & (1 << 3):
            offset = (offset + 1) & ~1
            offset += 4
        # Bit 4: FHSS (2 bytes)
        if present & (1 << 4):
            offset += 2
        # Bit 5: dBm Antenna Signal (1 byte, signed)
        if offset < rt_len:
            signal = struct.unpack_from("b", data, offset)[0]

    return rt_len, signal


def _parse_ies(body, offset):
    """Parse 802.11 Information Elements starting at offset.
    Returns dict with ssid, channel, encryption."""
    ssid = ""
    channel = 0
    has_rsn = False
    has_wpa = False

    while offset + 2 <= len(body):
        ie_id = body[offset]
        ie_len = body[offset + 1]
        ie_data = body[offset + 2:offset + 2 + ie_len]
        if len(ie_data) < ie_len:
            break

        if ie_id == IE_SSID:
            try:
                ssid = ie_data.decode("utf-8", errors="replace")
            except Exception:
                ssid = ""
        elif ie_id == IE_DS_PARAM and ie_len >= 1:
            channel = ie_data[0]
        elif ie_id == IE_RSN:
            has_rsn = True
        elif ie_id == IE_VENDOR and ie_len >= 4:
            if ie_data[:4] == WPA_OUI:
                has_wpa = True

        offset += 2 + ie_len

    if has_rsn:
        enc = "WPA2"
    elif has_wpa:
        enc = "WPA"
    else:
        enc = "OPN"

    return {"ssid": ssid, "channel": channel, "enc": enc}


def _parse_frame(data, aps, clients):
    """Parse a raw captured frame (radiotap + 802.11). Updates aps/clients dicts."""
    rt_len, signal = _parse_radiotap(data)
    if rt_len is None:
        return

    frame = data[rt_len:]
    if len(frame) < 24:
        return

    fc = struct.unpack_from("<H", frame, 0)[0]
    subtype = fc & 0xFC  # type + subtype bits (mask out flags)

    now = time.time()

    if subtype == SUBTYPE_BEACON or subtype == SUBTYPE_PROBE_RESP:
        # Beacon / Probe Response
        # addr1=DA(6), addr2=SA(6), addr3=BSSID(6)
        bssid = ":".join(f"{b:02x}" for b in frame[16:22])

        # Fixed params: timestamp(8) + beacon_interval(2) + capability(2) = 12 bytes
        # IEs start at offset 24 + 12 = 36
        if len(frame) < 36:
            return
        ie_info = _parse_ies(frame, 36)

        ssid = ie_info["ssid"]
        chan = ie_info["channel"]
        enc = ie_info["enc"]

        if bssid in aps:
            entry = aps[bssid]
            entry["count"] += 1
            entry["last_seen"] = now
            if signal is not None:
                entry["signal"] = signal
            # Update SSID if we got a non-empty one
            if ssid and not entry["ssid"]:
                entry["ssid"] = ssid
            if chan:
                entry["channel"] = chan
            if enc != "OPN":
                entry["enc"] = enc
        else:
            aps[bssid] = {
                "ssid": ssid,
                "channel": chan,
                "signal": signal if signal is not None else -100,
                "enc": enc,
                "last_seen": now,
                "count": 1,
            }

    elif subtype == SUBTYPE_PROBE_REQ:
        # Probe Request
        # addr1=DA(broadcast), addr2=SA(client MAC)
        client_mac = ":".join(f"{b:02x}" for b in frame[10:16])

        # IEs start at offset 24 (no fixed params for probe req)
        ie_info = _parse_ies(frame, 24)
        probe_ssid = ie_info["ssid"]

        if client_mac in clients:
            entry = clients[client_mac]
            entry["last_seen"] = now
            if signal is not None:
                entry["signal"] = signal
            if probe_ssid:
                entry["probes"].add(probe_ssid)
        else:
            probes = set()
            if probe_ssid:
                probes.add(probe_ssid)
            clients[client_mac] = {
                "probes": probes,
                "last_seen": now,
                "signal": signal if signal is not None else -100,
            }


# ── Channel hopper thread ───────────────────────────────────────────────────

def _channel_hopper(iface, stop_event, current_channel):
    """Cycle through channels on the monitor interface."""
    idx = 0
    while not stop_event.is_set():
        ch = ALL_CHANNELS[idx % len(ALL_CHANNELS)]
        current_channel["ch"] = ch
        try:
            subprocess.run(
                [IW, "dev", iface, "set", "channel", str(ch)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
        except Exception:
            pass
        idx += 1
        # Sleep in small increments so we can stop quickly
        for _ in range(int(HOP_INTERVAL * 10)):
            if stop_event.is_set():
                return
            time.sleep(0.1)


# ── Capture thread ──────────────────────────────────────────────────────────

def _capture_loop(iface, stop_event, aps, clients):
    """Raw socket capture loop. Reads frames and parses them."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((iface, 0))
        sock.settimeout(1.0)
    except Exception:
        return

    while not stop_event.is_set():
        try:
            data = sock.recv(4096)
        except socket.timeout:
            continue
        except Exception:
            break

        try:
            _parse_frame(data, aps, clients)
        except Exception:
            pass

    sock.close()


# ── LCD display helpers ──────────────────────────────────────────────────────

def _draw_scan_screen(pager, aps, clients, current_channel, start_time, scroll_offset):
    """Render the scan results on the pager LCD."""
    pager.clear(pager.BLACK)

    elapsed = int(time.time() - start_time)
    mins, secs = divmod(elapsed, 60)

    # Header bar
    pager.fill_rect(0, 0, 480, 18, pager.rgb(180, 0, 180))
    header = f"WIFI SCAN  {len(aps)} APs / {len(clients)} clients"
    pager.draw_text(4, 2, header, pager.BLACK, 2)

    # Sort APs by signal strength (strongest first)
    sorted_aps = sorted(aps.values(), key=lambda a: a["signal"], reverse=True)

    # Display area: y=20 to y=204 (184px), each row ~18px → ~10 rows
    ROW_H = 18
    MAX_ROWS = 10
    y = 20

    visible = sorted_aps[scroll_offset:scroll_offset + MAX_ROWS]
    for ap in visible:
        ssid = ap["ssid"] or "<hidden>"
        if len(ssid) > 20:
            ssid = ssid[:19] + "~"
        ch = ap["channel"] if ap["channel"] else "?"
        sig = ap["signal"]
        enc = ap["enc"]

        # Color by signal strength
        if sig > -50:
            color = pager.GREEN
        elif sig > -70:
            color = pager.CYAN
        elif sig > -80:
            color = pager.YELLOW
        else:
            color = pager.GRAY

        # Enc tag color
        enc_color = pager.RED if enc == "OPN" else pager.CYAN

        line = f"{ssid:<20s} ch{ch:<3}"
        pager.draw_text(4, y, line, color, 1)
        pager.draw_text(310, y, f"{sig}dBm", color, 1)
        pager.draw_text(400, y, enc, enc_color, 1)

        y += ROW_H

    # Status bar at bottom
    pager.fill_rect(0, 206, 480, 16, pager.rgb(40, 40, 40))
    ch_now = current_channel.get("ch", "?")
    status = f"CH:{ch_now}  {mins:02d}:{secs:02d}  [{scroll_offset+1}-{scroll_offset+len(visible)}/{len(sorted_aps)}]"
    pager.draw_text(4, 208, status, pager.GREEN, 1)
    pager.draw_text(360, 208, "ANY=STOP", pager.GRAY, 1)

    pager.flip()


# ── Main entry point ─────────────────────────────────────────────────────────

def run(config, ui_callback, stop_event, pager=None):
    """
    Passive WiFi scanner.

    Args:
        config: PagerPwn config dict
        ui_callback: function(line1, line2) for status updates
        stop_event: threading.Event — set to stop the scan
        pager: Pager object for direct LCD drawing

    Returns:
        dict: {"aps": {...}, "clients": {...}, "duration": int}
    """
    if pager is None:
        ui_callback("[WIFI SCAN]", "No pager ref — can't draw")
        time.sleep(2)
        return {"aps": {}, "clients": {}, "duration": 0}

    # Find or create a monitor interface
    we_created_it = False
    iface = _find_existing_mon()
    if iface:
        ui_callback("[WIFI SCAN]", f"Using {iface}")
    else:
        ui_callback("[WIFI SCAN]", f"Creating {MON_IFACE}...")
        iface = _create_mon_iface()
        if not iface:
            ui_callback("[WIFI SCAN]", "Failed to create monitor iface")
            time.sleep(2)
            return {"aps": {}, "clients": {}, "duration": 0}
        we_created_it = True
        ui_callback("[WIFI SCAN]", f"{iface} up (2.4GHz)")
    time.sleep(0.5)

    # Shared state
    aps = {}
    clients = {}
    current_channel = {"ch": 1}
    scan_stop = threading.Event()
    start_time = time.time()

    # Start worker threads
    cap_thread = threading.Thread(
        target=_capture_loop,
        args=(iface, scan_stop, aps, clients),
        daemon=True,
    )
    hop_thread = threading.Thread(
        target=_channel_hopper,
        args=(iface, scan_stop, current_channel),
        daemon=True,
    )
    cap_thread.start()
    hop_thread.start()

    # Display loop
    scroll_offset = 0
    pager.clear_input_events()
    prev_buttons = 0

    while not (stop_event and stop_event.is_set()):
        # Check for button press to stop
        buttons = pager.peek_buttons()
        if buttons and not prev_buttons:
            break
        prev_buttons = buttons

        # Auto-scroll: keep showing top (strongest signals)
        # User can't scroll manually in this version — top-N always shown
        _draw_scan_screen(pager, aps, clients, current_channel, start_time, scroll_offset)
        time.sleep(0.3)

    # Stop workers
    scan_stop.set()
    cap_thread.join(timeout=3)
    hop_thread.join(timeout=3)

    # Clean up monitor interface if we created it
    if we_created_it:
        _destroy_mon_iface(iface)

    duration = int(time.time() - start_time)

    # Save results to loot
    loot_dir = config.get("LOOT_DIR", "/mmc/root/loot/pagerpwn")
    os.makedirs(loot_dir, exist_ok=True)

    # Build loot dicts for return value
    loot_aps = {}
    for bssid, info in aps.items():
        loot_aps[bssid] = {k: v for k, v in info.items()}

    loot_clients = {}
    for mac, info in clients.items():
        loot_clients[mac] = {
            "probes": list(info["probes"]),
            "last_seen": info["last_seen"],
            "signal": info["signal"],
        }

    # Save as plaintext
    sorted_aps = sorted(loot_aps.items(), key=lambda x: x[1].get("signal", -100), reverse=True)
    loot_lines = [
        "WIFI SCAN REPORT",
        "================",
        f"Date:       {datetime.now().isoformat()}",
        f"Duration:   {duration}s",
        f"Interface:  {iface}",
        f"APs:        {len(loot_aps)}",
        f"Clients:    {len(loot_clients)}",
        "",
        "ACCESS POINTS",
        "-------------",
    ]
    for bssid, info in sorted_aps:
        ssid = info.get("ssid") or "<hidden>"
        ch = info.get("channel", "?")
        sig = info.get("signal", "?")
        enc = info.get("enc", "?")
        loot_lines.append(f"  {bssid}  {ssid:<24s} ch{ch:<3} {sig}dBm  {enc}")

    if loot_clients:
        loot_lines.append("")
        loot_lines.append("CLIENTS")
        loot_lines.append("-------")
        for mac, info in sorted(loot_clients.items()):
            sig = info.get("signal", "?")
            probes = ", ".join(info.get("probes", [])) or "(none)"
            loot_lines.append(f"  {mac}  {sig}dBm  probes: {probes}")

    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    loot_path = os.path.join(loot_dir, f"wifi_scan_{ts}.txt")
    try:
        with open(loot_path, "w") as f:
            f.write("\n".join(loot_lines) + "\n")
    except Exception:
        pass

    ui_callback(
        f"[WIFI] {len(aps)} APs / {len(clients)} clients",
        f"Saved to loot ({duration}s)",
    )
    time.sleep(1)

    return {"aps": loot_aps, "clients": loot_clients, "duration": duration}
