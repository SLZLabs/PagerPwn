"""
pagergotchi.py - Quick launcher for PagerGotchi (by Brainphreak)

Stops PagerPwn, launches run_pagergotchi.py from the sibling pagergotchi
payload directory, then returns control to PagerPwn when it exits.

Module interface: run(config, ui_callback, stop_event, pager=None) -> dict
"""

import os
import subprocess

RECON_DIR = "/mmc/root/payloads/user/reconnaissance"
GOTCHI_DIR = os.path.join(RECON_DIR, "pagergotchi")
GOTCHI_SCRIPT = os.path.join(GOTCHI_DIR, "run_pagergotchi.py")
PYTHON = "/mmc/usr/bin/python3"


def run(config, ui_callback, stop_event, pager=None):
    if not os.path.isfile(GOTCHI_SCRIPT):
        ui_callback("[PAGERGOTCHI]", "Not found on device")
        import time; time.sleep(2)
        return {"error": "not_found"}

    ui_callback("[PAGERGOTCHI]", "Launching...")

    # Release the pager LCD so pagergotchi can use it
    if pager:
        pager.clear(pager.BLACK)
        pager.flip()

    try:
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = "/mmc/lib:/mmc/usr/lib:" + env.get("LD_LIBRARY_PATH", "")
        subprocess.run(
            [PYTHON, GOTCHI_SCRIPT],
            cwd=GOTCHI_DIR,
            env=env,
            timeout=None,
        )
    except Exception as e:
        ui_callback("[PAGERGOTCHI]", f"Error: {str(e)[:30]}")
        import time; time.sleep(2)
        return {"error": str(e)}

    return {"launched": True}
