#!/bin/sh
# PagerPwn - payload.sh
# Bootstrap for Hak5 Pineapple Pager
# When launched from the Pineapple web UI: shows launch screen, waits for
# GREEN/RED, stops pineapplepager, runs PagerPwn, restarts pineapplepager.
# When launched from SSH: skips the UI prompt and goes straight to PagerPwn.

PAYLOAD_DIR="/mmc/root/payloads/user/reconnaissance/PagerPwn"

# Source config if present
[ -f "$PAYLOAD_DIR/config.sh" ] && . "$PAYLOAD_DIR/config.sh"

# ── Environment ───────────────────────────────────────────────────────────────
export LD_LIBRARY_PATH="/mmc/lib:/mmc/usr/lib:${LD_LIBRARY_PATH:-}"
PYTHON="/mmc/usr/bin/python3"

# Helper: log to pager UI if available, otherwise echo to terminal
log_msg() {
    if command -v LOG >/dev/null 2>&1; then
        LOG "$@"
    else
        # strip color arg if present
        case "$1" in
            red|green|yellow) shift ;;
        esac
        echo "$*"
    fi
}

# ── Python dependency check + install ─────────────────────────────────────────
# Required opkg packages for PagerPwn (all install to /mmc with -d mmc)
REQUIRED_PKGS="python3-base python3-ctypes python3-openssl python3-urllib python3-multiprocessing python3-codecs python3-logging"

install_deps() {
    log_msg "yellow" "Installing Python dependencies..."
    log_msg "Updating package lists..."
    opkg update >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        log_msg "red" "opkg update failed — need internet"
        log_msg "Connect pager to WiFi first."
        return 1
    fi

    for pkg in $REQUIRED_PKGS; do
        if ! opkg list-installed 2>/dev/null | grep -q "^$pkg "; then
            log_msg "Installing $pkg..."
            opkg install -d mmc "$pkg" >/dev/null 2>&1
            if [ $? -ne 0 ]; then
                log_msg "red" "Failed to install $pkg"
                return 1
            fi
        fi
    done

    log_msg "green" "Dependencies installed."
    return 0
}

if [ ! -x "$PYTHON" ]; then
    log_msg "yellow" "python3 not found — installing..."
    if ! install_deps; then
        log_msg ""
        log_msg "red" "ERROR: Could not install Python3"
        log_msg "Ensure the pager has an internet connection"
        log_msg "(WiFi client connected) and try again."
        log_msg ""
        command -v WAIT_FOR_INPUT >/dev/null 2>&1 && WAIT_FOR_INPUT >/dev/null 2>&1
        exit 1
    fi
fi

# Verify critical stdlib modules are available
$PYTHON -c "import ctypes, urllib.request, ssl" 2>/dev/null
if [ $? -ne 0 ]; then
    log_msg "yellow" "Missing Python modules — installing..."
    if ! install_deps; then
        log_msg "red" "ERROR: Could not install Python modules"
        command -v WAIT_FOR_INPUT >/dev/null 2>&1 && WAIT_FOR_INPUT >/dev/null 2>&1
        exit 1
    fi
    # Verify again after install
    $PYTHON -c "import ctypes, urllib.request, ssl" 2>/dev/null
    if [ $? -ne 0 ]; then
        log_msg "red" "ERROR: Python modules still missing after install"
        command -v WAIT_FOR_INPUT >/dev/null 2>&1 && WAIT_FOR_INPUT >/dev/null 2>&1
        exit 1
    fi
fi

# ── Pre-flight checks ────────────────────────────────────────────────────────
if [ ! -f "$PAYLOAD_DIR/pagerctl.py" ]; then
    log_msg "red" "ERROR: pagerctl.py not found in $PAYLOAD_DIR"
    exit 1
fi

if [ ! -f "$PAYLOAD_DIR/libpagerctl.so" ]; then
    log_msg "red" "ERROR: libpagerctl.so not found in $PAYLOAD_DIR"
    exit 1
fi

# ── Launch screen (only when running under pineapplepager UI) ─────────────────
if command -v LOG >/dev/null 2>&1 && command -v WAIT_FOR_INPUT >/dev/null 2>&1; then
    LOG ""
    LOG "green" "============================="
    LOG "green" "         PAGERPWN"
    LOG "green" "   Network Recon Toolkit"
    LOG "green" "============================="
    LOG ""
    LOG "  RECON SWEEP    LLMNR LISTEN"
    LOG "  JETDIRECT      CAMERA PROBE"
    LOG "  mDNS HARVEST   WIFI SCAN"
    LOG "  EXFIL LOOT     VIEW LOOT"
    LOG ""
    LOG "green" "  GREEN = Launch"
    LOG "red"   "  RED   = Cancel"
    LOG ""

    BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
    case "$BUTTON" in
        "GREEN"|"A")
            LOG ""
            LOG "Launching PagerPwn..."
            ;;
        *)
            LOG ""
            LOG "Cancelled."
            exit 0
            ;;
    esac
fi

# ── Network check — bail early if no usable interface ────────────────────────
has_network() {
    for iface in wlan0cli eth0; do
        ip -4 -o addr show "$iface" 2>/dev/null | grep -q "inet " && return 0
    done
    return 1
}

if ! has_network; then
    # Wait a few seconds in case interface is still coming up
    sleep 3
    if ! has_network; then
        log_msg "red" "NO NETWORK — wlan0cli and eth0 both down"
        log_msg "Connect the pager to a network first."
        command -v WAIT_FOR_INPUT >/dev/null 2>&1 && WAIT_FOR_INPUT >/dev/null 2>&1
        exit 1
    fi
fi

# ── Stop pineapplepager (safe — user acknowledged or running from SSH) ────────
/etc/init.d/pineapplepager stop 2>/dev/null
sleep 0.5

# ── Create loot directory ─────────────────────────────────────────────────────
mkdir -p /mmc/root/loot/pagerpwn

# ── Run PagerPwn ──────────────────────────────────────────────────────────────
cd "$PAYLOAD_DIR"
$PYTHON payload.py

# ── Restart pineapplepager ────────────────────────────────────────────────────
/etc/init.d/pineapplepager start 2>/dev/null
