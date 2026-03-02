#!/usr/bin/env python3
"""
gen_splash_video.py - Generate PagerPwn splash animation as MPEG-1 video

Pure Python + Pillow. No ffmpeg needed.
Outputs a minimal MPEG-1 Program Stream (.mpg) with I-frames only.

The video is 480x222 (Pager landscape) at 10 fps, ~3 seconds.
Animation: glitch bars → "PAGERPWN" text reveal → subtitle fade-in.

Usage:
    python3 tools/gen_splash_video.py
    # writes assets/splash.mpg
"""

import os
import sys
import struct
import math
from PIL import Image, ImageDraw, ImageFont

# ── Config ──────────────────────────────────────────────────────────────────
WIDTH = 480
HEIGHT = 224  # MPEG needs multiples of 16; we'll crop on playback
FPS = 10
TOTAL_FRAMES = 30  # 3 seconds at 10fps

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
OUT_FILE = os.path.join(OUT_DIR, "splash.mpg")

# Colors
BG = (0, 0, 20)
MAGENTA = (180, 0, 180)
CYAN = (0, 180, 180)
WHITE = (255, 255, 255)
GRAY = (128, 128, 128)
GREEN = (0, 255, 0)
BLACK = (0, 0, 0)


# ── Frame generation ────────────────────────────────────────────────────────

def _get_font(size):
    """Try to get a monospace font, fall back to default."""
    for path in [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
        "/usr/share/fonts/truetype/ubuntu/UbuntuMono-Bold.ttf",
    ]:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _draw_glitch_bars(draw, frame, w, h):
    """Random horizontal glitch bars in magenta/cyan."""
    import random
    random.seed(frame * 7 + 42)
    for _ in range(5 + frame * 2):
        y = random.randint(0, h - 1)
        bar_h = random.randint(1, 4)
        x_off = random.randint(-50, 50)
        color = MAGENTA if random.random() > 0.5 else CYAN
        alpha = max(30, 255 - frame * 20)
        # Simple colored bar
        draw.rectangle([max(0, x_off), y, min(w, w + x_off), y + bar_h],
                       fill=color)


def _draw_scanlines(draw, w, h, alpha_factor=0.3):
    """Subtle CRT scanlines."""
    for y in range(0, h, 3):
        draw.rectangle([0, y, w, y], fill=(0, 0, 0))


def _draw_matrix_rain(draw, frame, w, h):
    """Sparse green characters falling."""
    import random
    random.seed(1337)
    font = _get_font(12)
    chars = "01アイウエオカキクケコ>><{}//"
    columns = w // 10
    for col in range(columns):
        speed = random.randint(2, 6)
        x = col * 10
        start_frame = random.randint(0, 15)
        if frame < start_frame:
            continue
        y_pos = ((frame - start_frame) * speed * 12) % (h + 100) - 50
        # Draw 3-4 trailing chars
        for j in range(4):
            cy = y_pos - j * 14
            if 0 <= cy < h:
                c = chars[random.randint(0, len(chars) - 1)]
                brightness = max(0, 255 - j * 60)
                draw.text((x, cy), c, fill=(0, brightness, 0), font=font)


def generate_frame(frame_num):
    """Generate a single animation frame."""
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)

    progress = frame_num / TOTAL_FRAMES  # 0.0 → 1.0

    # Phase 1 (0-0.3): Glitch bars + matrix rain
    if progress < 0.3:
        _draw_matrix_rain(draw, frame_num, WIDTH, HEIGHT)
        _draw_glitch_bars(draw, frame_num, WIDTH, HEIGHT)

    # Phase 2 (0.2-0.6): Logo reveal with glitch
    elif progress < 0.6:
        # Fading matrix rain
        _draw_matrix_rain(draw, frame_num, WIDTH, HEIGHT)

        # Title text - "PAGERPWN"
        title_font = _get_font(48)
        text = "PAGERPWN"
        bbox = draw.textbbox((0, 0), text, font=title_font)
        tw = bbox[2] - bbox[0]
        tx = (WIDTH - tw) // 2

        # Glitch offset that decreases over time
        phase_progress = (progress - 0.2) / 0.4
        glitch = int((1 - phase_progress) * 20)
        import random
        random.seed(frame_num)
        x_jitter = random.randint(-glitch, glitch)
        y_jitter = random.randint(-glitch // 2, glitch // 2)

        # Draw with chromatic aberration effect
        ty = 60
        if glitch > 3:
            draw.text((tx + x_jitter - 2, ty + y_jitter), text,
                      fill=(255, 0, 0), font=title_font)
            draw.text((tx + x_jitter + 2, ty + y_jitter), text,
                      fill=(0, 0, 255), font=title_font)
        draw.text((tx + x_jitter, ty + y_jitter), text,
                  fill=MAGENTA, font=title_font)

    # Phase 3 (0.6-1.0): Stable logo + subtitle fade
    else:
        title_font = _get_font(48)
        sub_font = _get_font(20)
        ver_font = _get_font(28)

        text = "PAGERPWN"
        bbox = draw.textbbox((0, 0), text, font=title_font)
        tw = bbox[2] - bbox[0]
        tx = (WIDTH - tw) // 2

        # Stable title
        draw.text((tx, 55), text, fill=MAGENTA, font=title_font)

        # Version - fade in
        sub_progress = min(1.0, (progress - 0.6) / 0.2)
        if sub_progress > 0:
            v_text = "v1.0"
            vbox = draw.textbbox((0, 0), v_text, font=ver_font)
            vw = vbox[2] - vbox[0]
            vx = (WIDTH - vw) // 2
            c = int(sub_progress * 180)
            draw.text((vx, 115), v_text, fill=(0, c, c), font=ver_font)

        # "SLZLabs" - fade in later
        lab_progress = min(1.0, max(0, (progress - 0.75) / 0.2))
        if lab_progress > 0:
            s_text = "SLZLabs"
            sbox = draw.textbbox((0, 0), s_text, font=sub_font)
            sw = sbox[2] - sbox[0]
            sx = (WIDTH - sw) // 2
            c = int(lab_progress * 128)
            draw.text((sx, 155), s_text, fill=(c, c, c), font=sub_font)

        # Decorative line under title
        line_progress = min(1.0, (progress - 0.6) / 0.15)
        if line_progress > 0:
            line_w = int(line_progress * 200)
            cx = WIDTH // 2
            draw.rectangle([cx - line_w, 108, cx + line_w, 110], fill=CYAN)

    # Scanlines throughout
    _draw_scanlines(draw, WIDTH, HEIGHT)

    return img


# ── Minimal MPEG-1 encoder ──────────────────────────────────────────────────
#
# We encode I-frames only with the simplest possible DCT: all-zero AC
# coefficients, DC-only. This produces a valid but low-quality MPEG-1 stream.
# Perfect for a small embedded display.

def _rgb_to_ycbcr(img):
    """Convert PIL RGB image to YCbCr numpy-free."""
    w, h = img.size
    pixels = list(img.getdata())
    Y = []
    Cb = []
    Cr = []
    for r, g, b in pixels:
        y = int(0.299 * r + 0.587 * g + 0.114 * b)
        cb = int(-0.1687 * r - 0.3313 * g + 0.5 * b + 128)
        cr = int(0.5 * r - 0.4187 * g - 0.0813 * b + 128)
        Y.append(max(0, min(255, y)))
        Cb.append(max(0, min(255, cb)))
        Cr.append(max(0, min(255, cr)))
    return Y, Cb, Cr, w, h


def _subsample_420(channel, w, h):
    """4:2:0 chroma subsampling — average 2x2 blocks."""
    out = []
    for y in range(0, h, 2):
        for x in range(0, w, 2):
            p00 = channel[y * w + x]
            p10 = channel[y * w + min(x + 1, w - 1)]
            p01 = channel[min(y + 1, h - 1) * w + x]
            p11 = channel[min(y + 1, h - 1) * w + min(x + 1, w - 1)]
            out.append((p00 + p10 + p01 + p11) // 4)
    return out


class BitstreamWriter:
    """Writes individual bits to a byte buffer."""
    def __init__(self):
        self.data = bytearray()
        self.current_byte = 0
        self.bit_pos = 7  # MSB first

    def write_bits(self, value, num_bits):
        for i in range(num_bits - 1, -1, -1):
            bit = (value >> i) & 1
            self.current_byte |= (bit << self.bit_pos)
            self.bit_pos -= 1
            if self.bit_pos < 0:
                self.data.append(self.current_byte)
                self.current_byte = 0
                self.bit_pos = 7

    def flush(self):
        if self.bit_pos < 7:
            self.data.append(self.current_byte)
            self.current_byte = 0
            self.bit_pos = 7

    def get_bytes(self):
        self.flush()
        return bytes(self.data)


# MPEG-1 DC size VLC tables
_DC_LUM_SIZE_TABLE = [
    (0, 0b100, 3),
    (1, 0b00, 2),
    (2, 0b01, 2),
    (3, 0b101, 3),
    (4, 0b110, 3),
    (5, 0b1110, 4),
    (6, 0b11110, 5),
    (7, 0b111110, 6),
    (8, 0b1111110, 7),
]

_DC_CHROM_SIZE_TABLE = [
    (0, 0b00, 2),
    (1, 0b01, 2),
    (2, 0b10, 2),
    (3, 0b110, 3),
    (4, 0b1110, 4),
    (5, 0b11110, 5),
    (6, 0b111110, 6),
    (7, 0b1111110, 7),
    (8, 0b11111110, 8),
]


def _encode_dc(bs, dc_diff, is_luma):
    """Encode a DC coefficient difference using VLC."""
    table = _DC_LUM_SIZE_TABLE if is_luma else _DC_CHROM_SIZE_TABLE

    if dc_diff == 0:
        size = 0
    else:
        size = max(1, dc_diff.bit_length() if dc_diff > 0
                   else (-dc_diff).bit_length())
        # Cap at 8
        size = min(size, 8)

    # Write size VLC
    for s, code, bits in table:
        if s == size:
            bs.write_bits(code, bits)
            break

    # Write DC value
    if size > 0:
        if dc_diff > 0:
            bs.write_bits(dc_diff, size)
        else:
            # Negative: ones' complement
            bs.write_bits(dc_diff + (1 << size) - 1, size)


def _get_block_dc(channel, ch_w, bx, by, block_size=8):
    """Get average (DC) value of an 8x8 block."""
    total = 0
    count = 0
    for dy in range(block_size):
        for dx in range(block_size):
            px = bx * block_size + dx
            py = by * block_size + dy
            if px < ch_w and py * ch_w + px < len(channel):
                total += channel[py * ch_w + px]
                count += 1
    if count == 0:
        return 128
    return total // count


def encode_mpeg1(frames, width, height, fps=10):
    """
    Encode frames as MPEG-1 Program Stream.
    frames: list of PIL Images
    Returns: bytes
    """
    out = bytearray()

    # ── Pack header (simplified MPEG-1 PS) ──
    # System clock reference = 0
    # Pack start code
    out += b'\x00\x00\x01\xba'  # pack_start_code
    # MPEG-1 pack header: '0010' SCR[32..30] '1' SCR[29..15] '1' SCR[14..0] '1' mux_rate '1'
    # SCR = 0, mux_rate = 25200 (0x6270)
    scr = 0
    mux_rate = 25200
    pack_bits = (0b0010 << 44) | (((scr >> 30) & 0x7) << 41) | (1 << 40) | \
                (((scr >> 15) & 0x7FFF) << 25) | (1 << 24) | \
                ((scr & 0x7FFF) << 9) | (1 << 8) | \
                ((mux_rate >> 15) & 0x7F)
    out += struct.pack(">Q", pack_bits)[2:]  # 6 bytes

    mux_byte2 = ((mux_rate >> 7) & 0xFF)
    mux_byte3 = ((mux_rate & 0x7F) << 1) | 1
    out += bytes([mux_byte2, mux_byte3])

    # System header (optional but helps compatibility)
    out += b'\x00\x00\x01\xbb'  # system_header_start_code
    out += struct.pack(">H", 6)  # header_length
    # rate_bound (22 bits) + markers
    out += bytes([
        0x80 | ((mux_rate >> 15) & 0x7F),
        (mux_rate >> 7) & 0xFF,
        ((mux_rate & 0x7F) << 1) | 1,
        0x04 | 0x20 | 0x01,  # audio_bound=0, fixed=1, CSPS=0, audio_lock=1
        0x00 | 0xe1,  # video_bound=1, reserved
        0xff,  # reserved byte
    ])

    mb_width = (width + 15) // 16
    mb_height = (height + 15) // 16

    for frame_idx, img in enumerate(frames):
        # Convert to YCbCr
        Y, Cb, Cr, w, h = _rgb_to_ycbcr(img)
        Cb_sub = _subsample_420(Cb, w, h)
        Cr_sub = _subsample_420(Cr, w, h)

        ch_w = w // 2

        # Build video ES for this frame
        bs = BitstreamWriter()

        # ── Sequence header (repeat for each I-frame for seeking) ──
        # sequence_header_code
        bs.write_bits(0x000001B3, 32)
        # horizontal_size (12), vertical_size (12)
        bs.write_bits(width, 12)
        bs.write_bits(height, 12)
        # pel_aspect_ratio (4) = 1 (square), picture_rate (4) = 2 (25fps... closest)
        # For 10fps, we'll use code 1 (23.976) and just play at our own rate
        bs.write_bits(0x1, 4)  # aspect ratio = square
        # Frame rate code: 5 = 29.97 (close enough for embedded playback)
        bs.write_bits(0x5, 4)
        # bit_rate (18) = variable (0x3FFFF), marker, vbv_buffer_size (10), constrained (1)
        bs.write_bits(0x3FFFF, 18)  # bit_rate
        bs.write_bits(1, 1)  # marker
        bs.write_bits(20, 10)  # vbv_buffer_size
        bs.write_bits(0, 1)  # constrained_parameters_flag

        # No intra quantizer matrix, no non-intra
        bs.write_bits(0, 1)  # load_intra_quantizer_matrix = 0
        bs.write_bits(0, 1)  # load_non_intra_quantizer_matrix = 0

        # ── Picture header ──
        bs.write_bits(0x00000100, 32)  # picture_start_code
        bs.write_bits(frame_idx & 0x3FF, 10)  # temporal_reference
        bs.write_bits(1, 3)  # picture_coding_type = I-frame
        bs.write_bits(0xFFFF, 16)  # vbv_delay (variable)

        # ── Slice ──
        # One slice per MB row
        prev_dc_y = 128
        prev_dc_cb = 128
        prev_dc_cr = 128

        for mb_row in range(mb_height):
            # Slice start code
            bs.write_bits(0x00000101 + mb_row, 32)
            # quantizer_scale (5 bits)
            bs.write_bits(8, 5)
            # extra_bit_slice = 0
            bs.write_bits(0, 1)

            # Reset DC predictors at slice boundary
            prev_dc_y = 128
            prev_dc_cb = 128
            prev_dc_cr = 128

            for mb_col in range(mb_width):
                # Macroblock header
                # macroblock_address_increment = 1 (VLC: '1')
                bs.write_bits(1, 1)
                # macroblock_type for I-frame: intra (1) = '1'
                bs.write_bits(1, 1)

                # 4 luminance blocks (each 8x8 in the 16x16 MB)
                for block_idx in range(4):
                    bx = mb_col * 2 + (block_idx % 2)
                    by = mb_row * 2 + (block_idx // 2)
                    dc_val = _get_block_dc(Y, w, bx, by)
                    # Scale to MPEG DC range (divided by 8)
                    dc_scaled = dc_val // 8
                    dc_diff = dc_scaled - (prev_dc_y // 8)
                    prev_dc_y = dc_val
                    _encode_dc(bs, dc_diff, True)
                    # End of block (EOB) - no AC coefficients
                    bs.write_bits(0b10, 2)  # EOB marker

                # Cb block
                cb_bx = mb_col
                cb_by = mb_row
                dc_val = _get_block_dc(Cb_sub, ch_w, cb_bx, cb_by)
                dc_scaled = dc_val // 8
                dc_diff = dc_scaled - (prev_dc_cb // 8)
                prev_dc_cb = dc_val
                _encode_dc(bs, dc_diff, False)
                bs.write_bits(0b10, 2)  # EOB

                # Cr block
                dc_val = _get_block_dc(Cr_sub, ch_w, cb_bx, cb_by)
                dc_scaled = dc_val // 8
                dc_diff = dc_scaled - (prev_dc_cr // 8)
                prev_dc_cr = dc_val
                _encode_dc(bs, dc_diff, False)
                bs.write_bits(0b10, 2)  # EOB

        video_data = bs.get_bytes()

        # Wrap in PES packet (video stream = 0xE0)
        out += b'\x00\x00\x01\xe0'  # video PES start
        pes_len = len(video_data) + 1  # +1 for flags byte
        if pes_len > 65535:
            pes_len = 0  # unbounded
        out += struct.pack(">H", pes_len)
        out += bytes([0x0F])  # no PTS/DTS, padding
        out += video_data

        # Progress
        pct = (frame_idx + 1) * 100 // len(frames)
        sys.stdout.write(f"\r  Encoding frame {frame_idx + 1}/{len(frames)} ({pct}%)")
        sys.stdout.flush()

    # End code
    out += b'\x00\x00\x01\xb9'  # MPEG program end code

    print()
    return bytes(out)


# ── Alternate approach: MJPEG container ─────────────────────────────────────
# Since the Pager can natively display JPEG images, we ALSO create a simple
# frame bundle: a custom binary format the player module can easily parse.
# Format: "PPVD" magic, u16 fps, u16 frame_count, u16 width, u16 height,
#         then for each frame: u32 jpeg_size, jpeg_data[jpeg_size]

def encode_frame_bundle(frames, fps=10):
    """Encode frames as a simple JPEG frame bundle (.ppv = PagerPwn Video)."""
    import io
    buf = bytearray()
    buf += b"PPVD"  # magic
    buf += struct.pack("<HHH H", fps, len(frames), WIDTH, HEIGHT)

    for i, img in enumerate(frames):
        # Crop to actual display height
        cropped = img.crop((0, 0, WIDTH, min(HEIGHT, 222)))
        # Encode as JPEG
        jpeg_buf = io.BytesIO()
        cropped.save(jpeg_buf, format="JPEG", quality=70)
        jpeg_data = jpeg_buf.getvalue()
        buf += struct.pack("<I", len(jpeg_data))
        buf += jpeg_data

        pct = (i + 1) * 100 // len(frames)
        sys.stdout.write(f"\r  Bundling frame {i + 1}/{len(frames)} ({pct}%)")
        sys.stdout.flush()

    print()
    return bytes(buf)


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    print(f"[*] Generating {TOTAL_FRAMES} frames ({WIDTH}x{HEIGHT} @ {FPS}fps)")
    frames = []
    for i in range(TOTAL_FRAMES):
        frames.append(generate_frame(i))
        sys.stdout.write(f"\r  Rendering frame {i + 1}/{TOTAL_FRAMES}")
        sys.stdout.flush()
    print()

    # Generate MPEG-1 stream
    print("[*] Encoding MPEG-1...")
    mpeg_data = encode_mpeg1(frames, WIDTH, HEIGHT, FPS)
    mpg_path = OUT_FILE
    with open(mpg_path, "wb") as f:
        f.write(mpeg_data)
    print(f"[+] MPEG-1: {mpg_path} ({len(mpeg_data)} bytes)")

    # Also generate the frame bundle (much more reliable for playback)
    ppv_path = os.path.join(OUT_DIR, "splash.ppv")
    print("[*] Encoding frame bundle...")
    ppv_data = encode_frame_bundle(frames, FPS)
    with open(ppv_path, "wb") as f:
        f.write(ppv_data)
    print(f"[+] Bundle: {ppv_path} ({len(ppv_data)} bytes)")

    print(f"\n[*] Done! Files in {OUT_DIR}/")


if __name__ == "__main__":
    main()
