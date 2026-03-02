"""
arp_scan.py - ARP sweep for PagerPwn

Pure Python ARP scan with arping fallback.
Module interface: run(config, ui_callback, stop_event) -> dict
"""

import os
import re
import struct
import socket
import subprocess
import time
import fcntl

ETH_P_ARP = 0x0806
ARP_REQUEST = 1
ARP_REPLY = 2


def _get_hw_addr(iface):
    """Get MAC address of interface via ioctl."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", iface.encode()[:15]))
        s.close()
        return info[18:24]
    except Exception:
        return b"\x00" * 6


def _get_ip_addr(iface):
    """Get IP address of interface via ioctl."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", iface.encode()[:15]))
        s.close()
        return socket.inet_ntoa(info[20:24])
    except Exception:
        return None


def _raw_arp_scan(subnet, iface, timeout=2):
    """Send ARP requests on raw socket, collect replies. Returns {ip: mac}."""
    src_mac = _get_hw_addr(iface)
    src_ip = _get_ip_addr(iface)
    if not src_ip:
        return {}

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
        sock.bind((iface, 0))
        sock.settimeout(0.1)
    except (PermissionError, OSError):
        return None  # signal to use fallback

    src_ip_bytes = socket.inet_aton(src_ip)
    broadcast_mac = b"\xff" * 6

    # Send ARP requests to all 254 hosts
    for octet in range(1, 255):
        dst_ip = f"{subnet}.{octet}"
        dst_ip_bytes = socket.inet_aton(dst_ip)

        # Ethernet header: dst_mac + src_mac + ethertype
        eth = broadcast_mac + src_mac + struct.pack(">H", ETH_P_ARP)
        # ARP packet: hwtype(1) + proto(0x0800) + hwlen(6) + plen(4) + op(request)
        arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, ARP_REQUEST)
        arp += src_mac + src_ip_bytes + b"\x00" * 6 + dst_ip_bytes

        try:
            sock.send(eth + arp)
        except Exception:
            pass

    # Collect replies
    results = {}
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = sock.recv(65535)
            if len(data) < 42:
                continue
            # Check it's an ARP reply
            arp_op = struct.unpack(">H", data[20:22])[0]
            if arp_op != ARP_REPLY:
                continue
            sender_mac = data[22:28]
            sender_ip = socket.inet_ntoa(data[28:32])
            mac_str = ":".join(f"{b:02x}" for b in sender_mac)
            results[sender_ip] = mac_str
        except socket.timeout:
            continue
        except Exception:
            break

    sock.close()
    return results


def _arping_fallback(subnet, ui_callback):
    """Fallback: use arping binary or parse /proc/net/arp after pinging."""
    results = {}

    # Try arping first
    arping = None
    for path in ["/usr/bin/arping", "/usr/sbin/arping", "/mmc/usr/bin/arping"]:
        if os.path.exists(path):
            arping = path
            break

    if arping:
        for octet in range(1, 255):
            ip = f"{subnet}.{octet}"
            try:
                out = subprocess.run(
                    [arping, "-c", "1", "-w", "1", ip],
                    capture_output=True, text=True, timeout=2
                )
                # Parse MAC from arping output
                m = re.search(r"([\da-fA-F:]{17})", out.stdout)
                if m:
                    results[ip] = m.group(1).lower()
            except Exception:
                pass
        return results

    # Last resort: ping sweep + read ARP cache
    ui_callback("[ARP] Ping sweep", "Using ARP cache fallback")
    for octet in range(1, 255):
        ip = f"{subnet}.{octet}"
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, timeout=2
            )
        except Exception:
            pass

    # Parse ARP cache
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    results[parts[0]] = parts[3].lower()
    except Exception:
        pass

    return results


def run(config, ui_callback, stop_event=None):
    """
    ARP sweep the configured subnet.

    Returns:
        dict: {ip_str: mac_str}
    """
    subnet = config.get("SUBNET", "192.168.0")
    iface = config.get("IFACE", "br-lan")

    ui_callback("[ARP] Scanning", f"{subnet}.0/24 on {iface}")

    # Try raw socket first (needs root — pager runs as root)
    results = _raw_arp_scan(subnet, iface)

    if results is None:
        # Raw socket failed, use fallback
        ui_callback("[ARP] Fallback", "Using arping/ping")
        results = _arping_fallback(subnet, ui_callback)

    ui_callback(f"[ARP] Done", f"{len(results)} host(s) found")
    return results or {}
