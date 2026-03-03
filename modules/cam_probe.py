"""
cam_probe.py - Multi-manufacturer IP camera credential checker for PagerPwn

Fingerprints camera manufacturer (Reolink, Hikvision, Dahua, Generic),
then brute-forces credentials using the correct API for each brand.
Also checks RTSP availability.

Module interface: run(config, ui_callback, stop_event) -> dict
"""

import os
import ssl
import socket
import json
import time
import base64
import urllib.request
import urllib.error

HTTPS_PORT = 443
HTTP_PORT = 80
RTSP_PORT = 554
TIMEOUT = 2

# Skip cert verification for self-signed camera certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

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
        return [("admin", ""), ("admin", "admin"), ("admin", "12345"),
                ("admin", "123456"), ("admin", "password"), ("root", "root")]
    return [(u, p) for u in users for p in passwords]


CRED_LIST = _build_cred_list()

# ── Manufacturer constants ───────────────────────────────────────────────────
MFG_REOLINK = "reolink"
MFG_HIKVISION = "hikvision"
MFG_DAHUA = "dahua"
MFG_GENERIC = "generic"

# ── Fingerprinting ───────────────────────────────────────────────────────────


def _http_get_raw(ip, port, path, timeout=TIMEOUT):
    """Raw HTTP GET — returns (status_line, headers_str, body_str) or Nones."""
    try:
        if port == 443:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock = _SSL_CTX.wrap_socket(sock, server_hostname=ip)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

        request = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {ip}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 32768:
                    break
            except socket.timeout:
                break
        sock.close()

        text = response.decode(errors="replace")
        parts = text.split("\r\n\r\n", 1)
        header_block = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""
        status_line = header_block.split("\r\n", 1)[0] if header_block else ""
        return status_line, header_block, body

    except Exception:
        return None, None, None


def fingerprint(ip):
    """
    Identify camera manufacturer by probing HTTP/HTTPS.
    Returns one of: MFG_REOLINK, MFG_HIKVISION, MFG_DAHUA, MFG_GENERIC
    """
    for port in (HTTPS_PORT, HTTP_PORT):
        status, headers, body = _http_get_raw(ip, port, "/")
        if headers is None:
            continue

        combined = (headers + "\n" + body).lower()

        # Reolink
        if "reolink" in combined or "/api.cgi" in combined:
            return MFG_REOLINK

        # Hikvision
        if ("hikvision" in combined or "dnvrs-webs" in combined
                or "/doc/page/login.asp" in combined):
            return MFG_HIKVISION

        # Dahua
        if "dahua" in combined or "dhwebclientplugin" in combined:
            return MFG_DAHUA

        # Deeper Dahua check — some models only reveal on /login.htm
        if "/login.htm" in combined and "server: webserver" in combined:
            _, _, login_body = _http_get_raw(ip, port, "/login.htm")
            if login_body and "dahua" in login_body.lower():
                return MFG_DAHUA

    return MFG_GENERIC


# ── Reolink auth ─────────────────────────────────────────────────────────────


def _try_reolink_api(ip, user, password):
    """Try Reolink HTTPS API login. Returns (success, response_text)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, HTTPS_PORT))
        ssl_sock = _SSL_CTX.wrap_socket(sock, server_hostname=ip)

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
        ssl_sock.sendall(request.encode())

        response = b""
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            response += chunk

        ssl_sock.close()
        text = response.decode(errors="replace")

        json_start = text.find("[")
        if json_start == -1:
            json_start = text.find("{")
        if json_start >= 0:
            try:
                data = json.loads(text[json_start:])
                if isinstance(data, list):
                    data = data[0]
                code = data.get("code", -1)
                if code == 0:
                    return True, text
                return False, text
            except (json.JSONDecodeError, ValueError):
                pass

        # Fallback: string matching (firmware-dependent spacing)
        if '"code" : 0' in text or '"code":0' in text:
            return True, text

        return False, text

    except Exception as e:
        return False, str(e)


# ── Digest auth helper (Hikvision / Dahua) ───────────────────────────────────


def _try_digest_auth(ip, user, password, path, ports):
    """
    Try HTTP Digest + Basic auth against a path on given ports.
    Uses stdlib HTTPDigestAuthHandler. Returns (success, info).
    """
    for port in ports:
        try:
            scheme = "https" if port == HTTPS_PORT else "http"
            url = f"{scheme}://{ip}:{port}{path}"

            pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            pwd_mgr.add_password(None, url, user, password)
            digest_handler = urllib.request.HTTPDigestAuthHandler(pwd_mgr)
            basic_handler = urllib.request.HTTPBasicAuthHandler(pwd_mgr)

            if port == HTTPS_PORT:
                https_handler = urllib.request.HTTPSHandler(context=_SSL_CTX)
                opener = urllib.request.build_opener(
                    https_handler, digest_handler, basic_handler
                )
            else:
                opener = urllib.request.build_opener(
                    digest_handler, basic_handler
                )

            resp = opener.open(url, timeout=TIMEOUT + 1)
            if resp.getcode() == 200:
                body = resp.read(1024).decode(errors="replace")
                return True, body[:200]

        except urllib.error.HTTPError:
            continue
        except Exception:
            continue

    return False, "auth failed"


# ── Hikvision auth ───────────────────────────────────────────────────────────


def _try_hikvision(ip, user, password):
    """Try Hikvision Digest auth against ISAPI. Returns (success, info)."""
    return _try_digest_auth(
        ip, user, password,
        "/ISAPI/System/deviceInfo",
        [HTTPS_PORT, HTTP_PORT],
    )


# ── Dahua auth ───────────────────────────────────────────────────────────────


def _try_dahua(ip, user, password):
    """Try Dahua Digest auth against CGI. Returns (success, info)."""
    return _try_digest_auth(
        ip, user, password,
        "/cgi-bin/magicBox.cgi?action=getDeviceType",
        [HTTPS_PORT, HTTP_PORT],
    )


# ── Generic auth (HTTP Basic on common snapshot paths) ───────────────────────


def _try_generic(ip, user, password):
    """Try Basic auth against common camera paths. Returns (success, info)."""
    paths = [
        "/snap.jpg",
        "/image.jpg",
        "/capture",
        "/jpg/image.jpg",
        "/onvif/snapshot",
        "/",
    ]
    cred_b64 = base64.b64encode(f"{user}:{password}".encode()).decode()

    for port in (HTTPS_PORT, HTTP_PORT):
        for path in paths:
            try:
                scheme = "https" if port == HTTPS_PORT else "http"
                url = f"{scheme}://{ip}:{port}{path}"
                req = urllib.request.Request(url)
                req.add_header("Authorization", f"Basic {cred_b64}")

                ctx = _SSL_CTX if port == HTTPS_PORT else None
                resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
                if resp.getcode() == 200:
                    return True, f"Basic auth OK on {path} (port {port})"
            except Exception:
                continue

    return False, "no path responded"


# ── RTSP check ───────────────────────────────────────────────────────────────


def _try_rtsp(ip, user, password):
    """Try RTSP OPTIONS — checks if auth is required."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, RTSP_PORT))

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

        if "200 OK" in text:
            return {"auth_required": False, "response": text[:200]}
        elif "401" in text:
            return {"auth_required": True, "response": text[:200]}

        return {"auth_required": None, "response": text[:200]}

    except Exception as e:
        return {"error": str(e)}


# ── Auth dispatcher ──────────────────────────────────────────────────────────

_AUTH_FUNCS = {
    MFG_REOLINK:   _try_reolink_api,
    MFG_HIKVISION: _try_hikvision,
    MFG_DAHUA:     _try_dahua,
    MFG_GENERIC:   _try_generic,
}


# ── Main entry point ────────────────────────────────────────────────────────


def run(config, ui_callback, stop_event=None):
    """
    Probe IP camera for default credentials.

    Returns:
        dict: {"auth_success": bool, "cred": str, "method": str,
               "manufacturer": str, "device_info": str, "rtsp_status": dict}
    """
    target_ip = config.get("TARGETS", {}).get("Camera", "")
    result = {
        "auth_success": False,
        "cred": "",
        "method": "",
        "manufacturer": MFG_GENERIC,
        "device_info": "",
        "rtsp_status": {},
    }

    # ── Connectivity check ────────────────────────────────────────────────
    ui_callback("[CAMERA]", f"Checking {target_ip}...")
    reachable = False
    for port in (HTTPS_PORT, HTTP_PORT):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target_ip, port))
            s.close()
            reachable = True
            break
        except Exception:
            continue

    if not reachable:
        ui_callback("[CAMERA] OFFLINE", f"{target_ip} unreachable")
        time.sleep(2)
        return result

    # ── Fingerprint manufacturer ──────────────────────────────────────────
    ui_callback("[CAMERA]", "Fingerprinting...")
    mfg = fingerprint(target_ip)
    result["manufacturer"] = mfg
    mfg_label = mfg.upper()
    ui_callback(f"[CAMERA] {mfg_label}", f"Identified as {mfg_label}")
    time.sleep(0.5)

    # ── HTTP Credential Check ─────────────────────────────────────────────
    auth_func = _AUTH_FUNCS.get(mfg, _try_generic)
    total = len(CRED_LIST)
    for idx, (user, password) in enumerate(CRED_LIST, 1):
        if stop_event and stop_event.is_set():
            break

        cred_str = f"{user}:{password}" if password else f"{user}:(blank)"
        ui_callback(f"[{mfg_label}] {idx}/{total}", f"Trying {cred_str}")

        success, resp = auth_func(target_ip, user, password)
        if success:
            result["auth_success"] = True
            result["cred"] = f"{user}:{password}"
            result["method"] = f"HTTP API ({mfg_label})"
            result["device_info"] = str(resp)[:200] if resp else ""
            ui_callback(f"[{mfg_label}] AUTH OK!", f"Cred: {cred_str}")
            time.sleep(0.5)
            return result

        time.sleep(0.01)

    # ── RTSP Check ────────────────────────────────────────────────────────
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
