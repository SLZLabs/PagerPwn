"""
port_scan.py - Threaded socket-based port scanner for PagerPwn

Scans known LAN targets against per-host port profiles.
Module interface: run(config, ui_callback, stop_event) -> dict
"""

import socket
import threading

PORT_PROFILES = {
    "ad":      [88, 135, 389, 445, 636, 3389, 5985],
    "esxi":    [22, 443, 902, 5989],
    "vcenter": [22, 443, 5480, 9443],
    "printer": [80, 443, 515, 9100],
    "camera":  [80, 554, 8080, 443],
    "ha":      [8123, 8124],
    "generic": [21, 22, 23, 80, 443, 445, 3389, 8080, 8443],
}

# Keyword → profile mapping
_PROFILE_KEYS = [
    (("ad", "brains", "dc"),            "ad"),
    (("esxi",),                          "esxi"),
    (("vcenter",),                       "vcenter"),
    (("printer", "hp"),                  "printer"),
    (("camera", "reolink"),              "camera"),
    (("home", "assistant", "ha"),        "ha"),
]


def _pick_profile(name):
    name_l = name.lower()
    for keywords, profile in _PROFILE_KEYS:
        if any(k in name_l for k in keywords):
            return PORT_PROFILES[profile]
    return PORT_PROFILES["generic"]


def _scan_host(ip, ports, timeout):
    """Scan all ports on a host concurrently. Returns sorted list of open ports."""
    open_ports = []
    lock = threading.Lock()

    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                with lock:
                    open_ports.append(port)
            s.close()
        except Exception:
            pass

    threads = [threading.Thread(target=check, args=(p,), daemon=True) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 0.5)

    return sorted(open_ports)


def classify_host(ports):
    """Classify a host by its open ports. Returns a device-type string."""
    ps = set(ports)
    if 9100 in ps:
        return "printer"
    if 554 in ps:
        return "camera"
    if 8123 in ps:
        return "ha"
    if {88, 389, 445}.issubset(ps):
        return "ad"
    if 902 in ps:
        return "esxi"
    return "generic"


def run(config, ui_callback, stop_event=None):
    """
    Scan all TARGETS in config for open ports.

    Returns:
        dict: {name: {"ip": str, "ports": [int, ...]}}
    """
    targets = config.get("TARGETS", {})
    timeout = float(config.get("PORT_SCAN_TIMEOUT", 1.0))
    results = {}

    for name, ip in targets.items():
        if stop_event and stop_event.is_set():
            break

        ui_callback(f"Scanning {ip}", name[:22])
        ports = _pick_profile(name)
        open_ports = _scan_host(ip, ports, timeout)
        results[name] = {"ip": ip, "ports": open_ports}

        if open_ports:
            ui_callback(f"{ip} OPEN", ", ".join(str(p) for p in open_ports[:6]))
        else:
            ui_callback(f"{ip}", "No open ports")

    return results
