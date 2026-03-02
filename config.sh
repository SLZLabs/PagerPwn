#!/bin/bash
# PagerPwn - config.sh
# Optional env-var overrides. Edit config.json for persistent settings.
# If SMB_PASS is sensitive, export it here instead of putting it in config.json.

# Network
# SUBNET="192.168.0"
# IFACE="wlan1"

# Exfil / SMB (uncomment and fill in to enable)
# SMB_HOST=""
# SMB_SHARE=""
# SMB_USER=""
# SMB_PASS=""

# Set to 1 to auto-install opkg/pip deps on first run
INSTALL_DEPS=0
