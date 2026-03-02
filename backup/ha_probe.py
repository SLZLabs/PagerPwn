"""
ha_probe.py - Home Assistant unauthenticated API check (BACKUP)

Removed from main PagerPwn menu. To restore, add run_ha_probe back
to the menu items list in payload.py and copy this function back.
"""

import socket
import time
import json
import urllib.request
import urllib.error


def run_ha_probe(config, ui_callback, stop_event):
    """Home Assistant unauthenticated API check."""
    ha_hosts = config.get("DISCOVERED", {}).get("ha", [])
    ha_ip = ha_hosts[0] if ha_hosts else config.get("HA_IP", "")
    if not ha_ip:
        ui_callback("[HA PROBE]", "No HA found — run RECON")
        time.sleep(2)
        return None
    ha_port = 8123
    ui_callback("[HA PROBE]", f"{ha_ip}:{ha_port}")

    # Connectivity check
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ha_ip, ha_port))
        s.close()
    except Exception:
        ui_callback("HA PROBE", "Port closed / unreachable")
        time.sleep(2)
        return None

    # Try unauthenticated REST API
    try:
        req = urllib.request.Request(
            f"http://{ha_ip}:{ha_port}/api/",
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=3)
        body = resp.read().decode(errors="replace")

        ui_callback("[HA] OPEN", "No auth required!")
        result = {"auth": "none", "ip": ha_ip, "response": body[:500]}
        return result

    except urllib.error.HTTPError as e:
        if e.code == 401:
            ui_callback("[HA] Auth required", "Token needed — not default")
        else:
            ui_callback("[HA] HTTP error", f"Code {e.code}")
    except Exception as e:
        ui_callback("[HA] Error", str(e)[:30])

    time.sleep(2)
    return None
