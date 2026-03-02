"""
video_player.py - PagerPwn Video (.ppv) player module

Plays JPEG frame bundles on the Pager LCD at native frame rate.
Format: "PPVD" magic, u16 fps, u16 frame_count, u16 width, u16 height,
        then per frame: u32 jpeg_size, jpeg_data[jpeg_size]

Module interface: run(config, ui_callback, stop_event, pager=None) -> dict
"""

import os
import struct
import time

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPLASH_PATH = os.path.join(_BASE, "assets", "splash.ppv")
FRAME_TMP = "/tmp/ppv_frame.jpg"


def _parse_header(f):
    """Read PPV header. Returns (fps, frame_count, width, height) or None."""
    magic = f.read(4)
    if magic != b"PPVD":
        return None
    fps, count, w, h = struct.unpack("<HHHH", f.read(8))
    return fps, count, w, h


def _read_frame(f):
    """Read next frame from PPV. Returns JPEG bytes or None."""
    size_data = f.read(4)
    if len(size_data) < 4:
        return None
    size = struct.unpack("<I", size_data)[0]
    if size == 0 or size > 1_000_000:
        return None
    return f.read(size)


def run(config, ui_callback, stop_event, pager=None):
    """
    Play the splash animation on the Pager LCD.

    Returns:
        dict: {"frames_played": int, "path": str}
    """
    video_path = config.get("VIDEO_PATH", SPLASH_PATH)
    stats = {"frames_played": 0, "path": video_path}

    if pager is None:
        ui_callback("[VIDEO]", "No pager ref")
        time.sleep(2)
        return stats

    if not os.path.isfile(video_path):
        ui_callback("[VIDEO]", f"Not found: {os.path.basename(video_path)}")
        time.sleep(2)
        return stats

    with open(video_path, "rb") as f:
        header = _parse_header(f)
        if header is None:
            ui_callback("[VIDEO]", "Bad PPV file")
            time.sleep(2)
            return stats

        fps, frame_count, vid_w, vid_h = header
        frame_interval = 1.0 / max(1, fps)

        ui_callback("[VIDEO]", f"{frame_count}f @ {fps}fps")

        pager.clear_input_events()

        for i in range(frame_count):
            if stop_event and stop_event.is_set():
                break

            # Check for button press to skip
            event = pager.get_input_event()
            if event:
                btn, etype, _ = event
                if etype == pager.EVENT_PRESS:
                    break

            frame_start = time.time()

            jpeg_data = _read_frame(f)
            if jpeg_data is None:
                break

            # Write JPEG to temp file and blit to screen
            with open(FRAME_TMP, "wb") as tmp:
                tmp.write(jpeg_data)

            pager.clear(0x0000)
            pager.draw_image_file_scaled(0, 0, 480, 222, FRAME_TMP)
            pager.flip()

            stats["frames_played"] += 1

            # Frame timing
            elapsed = time.time() - frame_start
            remaining = frame_interval - elapsed
            if remaining > 0:
                time.sleep(remaining)

    # Clean up temp file
    try:
        os.remove(FRAME_TMP)
    except Exception:
        pass

    return stats
