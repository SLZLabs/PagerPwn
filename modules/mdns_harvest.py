"""
mdns_harvest.py - Passive mDNS/DNS-SD device harvester for PagerPwn

Listens on 224.0.0.251:5353 for mDNS announcements.
Zero active packets sent — purely passive intel collection.
Module interface: run(config, ui_callback, stop_event, duration=30) -> dict
"""

import socket
import struct
import time

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

# DNS record types we care about
TYPE_PTR = 12
TYPE_SRV = 33
TYPE_A   = 1
TYPE_TXT = 16


def _parse_name(data, offset):
    """Parse DNS wire-format name with pointer compression. Returns (name_str, new_offset)."""
    labels = []
    visited = set()
    jumped = False
    orig_offset = offset

    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)

        length = data[offset]

        if length == 0:
            if not jumped:
                offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # Pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                offset += 2
            jumped = True
            offset = ptr
        else:
            offset += 1
            end = offset + length
            if end > len(data):
                break
            try:
                labels.append(data[offset:end].decode("utf-8", errors="replace"))
            except Exception:
                pass
            offset = end

    return ".".join(labels), offset


def run(config, ui_callback, stop_event=None, duration=30):
    """
    Passively listen for mDNS announcements.

    Returns:
        dict: {src_ip: set_of_service_names}
    """
    devices = {}  # ip -> set of service strings

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MDNS_PORT))

        mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1.0)
    except Exception as e:
        ui_callback("[mDNS] BIND FAILED", str(e)[:30])
        time.sleep(2)
        return devices

    deadline = time.time() + duration
    ui_callback("[mDNS] LISTENING", "0 devices found")

    while time.time() < deadline:
        if stop_event and stop_event.is_set():
            break

        try:
            data, (src_ip, _) = sock.recvfrom(4096)
        except socket.timeout:
            ui_callback("[mDNS] LISTENING", f"{len(devices)} device(s) found")
            continue
        except Exception:
            break

        if len(data) < 12:
            continue

        try:
            qdcount = struct.unpack(">H", data[4:6])[0]
            ancount = struct.unpack(">H", data[6:8])[0]
            arcount = struct.unpack(">H", data[10:12])[0]
            offset = 12

            # Skip question section
            for _ in range(qdcount):
                _, offset = _parse_name(data, offset)
                offset += 4  # QTYPE + QCLASS

            # Parse answer + additional sections
            for _ in range(ancount + arcount):
                if offset >= len(data):
                    break
                name, offset = _parse_name(data, offset)
                if offset + 10 > len(data):
                    break

                rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
                offset += 10
                rdata_end = offset + rdlen

                if src_ip not in devices:
                    devices[src_ip] = set()

                if rtype == TYPE_PTR and offset < rdata_end:
                    ptr_name, _ = _parse_name(data, offset)
                    if ptr_name:
                        devices[src_ip].add(ptr_name)

                elif rtype == TYPE_SRV and offset + 6 <= rdata_end:
                    srv_name, _ = _parse_name(data, offset + 6)
                    if srv_name:
                        devices[src_ip].add(f"SRV:{srv_name}")

                elif rtype == TYPE_A and rdlen == 4 and offset + 4 <= len(data):
                    ip_str = ".".join(str(b) for b in data[offset:offset + 4])
                    devices[src_ip].add(f"A:{ip_str}")

                offset = rdata_end

        except Exception:
            pass

        ui_callback("[mDNS] LISTENING", f"{len(devices)} device(s) found")

    sock.close()
    return devices
