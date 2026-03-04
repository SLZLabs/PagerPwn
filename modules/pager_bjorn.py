"""
pager_bjorn.py - Quick launcher for Pager Bjorn

Stops PagerPwn, launches bjorn_menu.py from the sibling pager_bjorn
payload directory, then returns control to PagerPwn when it exits.

Module interface: run(config, ui_callback, stop_event, pager=None) -> dict
"""

import os
import subprocess

RECON_DIR = "/mmc/root/payloads/user/reconnaissance"
BJORN_DIR = os.path.join(RECON_DIR, "pager_bjorn")
BJORN_SCRIPT = os.path.join(BJORN_DIR, "bjorn_menu.py")
PYTHON = "/mmc/usr/bin/python3"


def run(config, ui_callback, stop_event, pager=None):
    if not os.path.isfile(BJORN_SCRIPT):
        ui_callback("[PAGER BJORN]", "Not found on device")
        import time; time.sleep(2)
        return {"error": "not_found"}

    ui_callback("[PAGER BJORN]", "Launching...")

    # Release the pager LCD so bjorn can use it
    if pager:
        pager.clear(pager.BLACK)
        pager.flip()

    try:
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = "/mmc/lib:/mmc/usr/lib:" + env.get("LD_LIBRARY_PATH", "")
        subprocess.run(
            [PYTHON, BJORN_SCRIPT],
            cwd=BJORN_DIR,
            env=env,
            timeout=None,
        )
    except Exception as e:
        ui_callback("[PAGER BJORN]", f"Error: {str(e)[:30]}")
        import time; time.sleep(2)
        return {"error": str(e)}

    return {"launched": True}
