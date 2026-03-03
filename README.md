# PagerPwn

A pocket-sized network recon and exploitation toolkit for the [Hak5 WiFi Pineapple Pager](https://shop.hak5.org/products/wifi-pineapple-pager).

Turns the pager into a handheld hacking console — full LCD menu, button navigation, live capture display, credential brute forcing, and on-device loot browser. No laptop required.

> **Authorized testing only.** This tool is intended for security research, penetration testing engagements, and home lab use. Don't be that guy.

## Features

- **Auto-detect networking** — picks up `wlan0cli` or `eth0` at launch, no config needed
- **ARP + port scan** — full /24 subnet sweep with automatic device classification
- **LLMNR/NBT-NS poisoning** — captures NTLMv2 hashes (hashcat -m 5600 ready)
- **Credential brute force** — multi-manufacturer camera login (Reolink, Hikvision, Dahua, Generic) with auto-fingerprinting
- **Printer exploitation** — HP JetDirect PJL enumeration + LCD hijack
- **Live camera viewer** — streams JPEG snapshots directly to the pager screen
- **mDNS harvesting** — passive device discovery (zero packets sent)
- **WiFi scanning** — passive 802.11 monitor-mode scanner with channel hopping (2.4 + 5GHz)
- **Animated splash intro** — glitch/matrix rain video plays on boot (skippable)
- **SMB exfiltration** — syncs captured loot to a remote share
- **On-device loot browser** — review captures without SSH

## Quick Start

1. Clone or download this repo
2. Copy to the pager:
   ```bash
   scp -r PagerPwn root@<pager-ip>:/mmc/root/payloads/user/reconnaissance/
   ```
3. Launch from the Pineapple web UI under Payloads, or SSH in:
   ```bash
   ssh root@<pager-ip>
   /mmc/root/payloads/user/reconnaissance/PagerPwn/payload.sh
   ```

That's it. The bootstrap script auto-installs any missing Python dependencies,
stops pineapplepager (web UI goes quiet — that's normal), runs PagerPwn, and
restarts pineapplepager on exit.

### Dependencies

All dependencies are auto-installed on first run via `opkg install -d mmc` (requires internet):

- `python3-base`, `python3-ctypes`, `python3-openssl`, `python3-urllib`
- `python3-multiprocessing`, `python3-codecs`, `python3-logging`

The `pagerctl` library (`libpagerctl.so` + `pagerctl.py`) is bundled — no extra setup needed.

## Boot Flow

1. **Splash** — Animated glitch intro video (matrix rain → chromatic logo reveal → title card)
2. **Interface select** — auto-detects `wlan0cli` and `eth0`. If both are up, you pick which network to scan. If only one has an IP, it auto-selects
3. **Confirmation** — shows selected interface, IP, and target subnet
4. **Main menu** — ready to go

## Controls

| Button | Action |
|--------|--------|
| A | Move cursor / cycle selection |
| B | Select / execute |
| Hold B (1.5s) | Abort running module / back |

## Modules

| Module | Description |
|--------|-------------|
| **RECON SWEEP** | ARP sweep + port scan all live hosts, classifies devices automatically |
| **LLMNR LISTEN** | LLMNR/NBT-NS poisoner with mini SMB server — captures NTLMv2 hashes |
| **JETDIRECT PROBE** | HP printer PJL enumeration, config dump, filesystem listing, LCD prank |
| **CAMERA PROBE** | Multi-manufacturer camera fingerprint + credential brute force (Reolink, Hikvision, Dahua, Generic) |
| **CAM SNAPSHOT** | Live camera JPEG viewer on the pager LCD — auto-selects snapshot API per manufacturer |
| **mDNS HARVEST** | Passive mDNS listener — catalogs devices without sending any packets |
| **WIFI SCAN** | Passive 802.11 scanner — discovers APs, clients, and probe requests via monitor mode (2.4GHz) |
| **EXFIL LOOT** | Syncs all captured loot to a remote SMB share |
| **VIEW LOOT** | Browse and review captured files on-device |
| **QUIET MODE** | Toggle passive-only (disables LLMNR poisoning + active scans) |

### WiFi Scan Notes

The Pager has two radios: `phy0` (2.4GHz, MediaTek MT7628) and `phy1` (dual-band, MediaTek MT7915). Only `phy0` exposes monitor mode to userspace — `phy1` relies on the `pineapd` firmware daemon for monitor functionality, which isn't available while PagerPwn is running.

WIFI SCAN automatically creates a temporary monitor interface (`ppwn0mon`) on `phy0` at launch and tears it down on exit. This means scanning is **2.4GHz only** (channels 1-11). Most consumer APs broadcast on 2.4GHz anyway, so coverage is solid for general recon.

### Camera Manufacturer Support

CAMERA PROBE auto-fingerprints the camera brand before brute-forcing, so it uses the right API for each manufacturer:

| Manufacturer | Auth Method | Snapshot Endpoint |
|---|---|---|
| **Reolink** | Token-based JSON API (`/api.cgi?cmd=Login`) | `/api.cgi?cmd=Snap&channel=0&token=T` |
| **Hikvision** | HTTP Digest | `/ISAPI/Streaming/channels/101/picture` |
| **Dahua** | HTTP Digest | `/cgi-bin/snapshot.cgi?channel=1` |
| **Generic** | HTTP Basic | `/snap.jpg`, `/image.jpg`, `/capture`, etc. |

Fingerprinting hits port 80/443 and checks response headers + body for manufacturer markers (no auth needed). Once identified, the correct driver is used for both credential brute force and snapshot capture. CAM SNAPSHOT inherits the manufacturer from CAMERA PROBE so it doesn't need to re-fingerprint.

## Auto-Targeting

Run **RECON SWEEP** first. It ARP-sweeps the subnet, port-scans every discovered host, and classifies devices by open ports:

| Open Port(s) | Device Type |
|--------------|-------------|
| 9100 | `printer` |
| 554 | `camera` |
| 8123 | `ha` (Home Assistant) |
| 88 + 389 + 445 | `ad` (Active Directory) |
| 902 | `esxi` (VMware) |
| other | `generic` |

After recon, attack modules automatically target the first discovered device of each type. No hardcoded IPs — just scan and go.

## Wordlists

Credential brute force modules load combos from `wordlists/`:

```
wordlists/
├── usernames.txt   # one username per line (admin, root, ubnt, etc.)
└── passwords.txt   # one password per line (blank line = empty password)
```

Ships with default lists sourced from Mirai botnet credentials, common IoT/camera defaults, and standard admin passwords (~26 usernames x ~48 passwords). Edit these to add your own or swap in larger lists.

If the wordlists directory is missing, modules fall back to a small built-in default list.

## Configuration

Optional — PagerPwn works out of the box with zero config. Edit `config.json` if you want SMB exfil or custom timeouts:

```json
{
  "LOOT_DIR": "/mmc/root/loot/pagerpwn",
  "SMB_HOST": "",
  "SMB_SHARE": "",
  "SMB_USER": "",
  "SMB_PASS": "",
  "PORT_SCAN_TIMEOUT": 1.0
}
```

For sensitive values like `SMB_PASS`, export them as env vars in `config.sh` instead.

## Loot

All captures saved to `/mmc/root/loot/pagerpwn/` (configurable).

| File Pattern | Contents |
|---|---|
| `recon_<ts>.json` | Full port scan results + device classifications |
| `llmnr_<ts>.hash` | NTLMv2 hashes (hashcat -m 5600 format) |
| `printer_<ts>.txt` | HP PJL config dump + serial + filesystem |
| `camera_<ts>.txt` | Camera auth brute force results |
| `cam_snap_<ts>.txt` | Camera snapshot session stats |
| `mdns_<ts>.json` | Passive mDNS device catalog |
| `wifi_scan_<ts>.json` | Discovered APs, clients, and probe requests |

## File Structure

```
PagerPwn/
├── payload.sh            # bootstrap, dep installer, cleanup
├── payload.py            # main orchestrator + interface picker + menu
├── config.json           # user configuration (optional)
├── config.sh             # env-var overrides (optional)
├── pagerctl.py           # pager hardware control wrapper
├── libpagerctl.so        # compiled MIPS shared library
├── wordlists/
│   ├── usernames.txt     # default/IoT admin usernames
│   └── passwords.txt     # default/weak passwords
├── assets/
│   ├── splash.ppv        # animated intro (JPEG frame bundle)
│   └── splash.mpg        # MPEG-1 version of intro
├── modules/
│   ├── arp_scan.py       # raw socket ARP sweep
│   ├── port_scan.py      # threaded port scanner + device classifier
│   ├── llmnr.py          # LLMNR/NBT-NS poisoner + NTLMv2 capture
│   ├── jetdirect.py      # HP JetDirect PJL exploitation
│   ├── cam_probe.py      # multi-manufacturer camera fingerprint + credential brute force
│   ├── cam_snap.py       # multi-manufacturer live camera snapshot viewer
│   ├── mdns_harvest.py   # passive mDNS device catalog
│   ├── wifi_scan.py      # passive 802.11 AP + client scanner
│   ├── video_player.py   # PPV splash video player
│   └── exfil.py          # loot writer + SMB exfil trigger
├── tools/
│   └── gen_splash_video.py  # generates splash.ppv + splash.mpg
└── ui/
    ├── menu.py           # LCD menu system
    └── scroll.py         # scrollable result viewer
```

## Hardware

- [Hak5 WiFi Pineapple Pager](https://shop.hak5.org/products/wifi-pineapple-pager) (MIPS OpenWrt, `mipsel_24kc`)
- Python 3.11 on `/mmc` (auto-installed if missing)
- `pagerctl` for LCD, LED, button, and buzzer control (bundled)

## Credits

Built by [SLZLabs](https://github.com/SLZLabs).

## License

For authorized security testing and research only.
