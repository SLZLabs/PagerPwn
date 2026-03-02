"""
scroll.py - Scrollable result viewer for PagerPwn

Displays a list of text lines with A=scroll, B=back.
Highlights lines containing key findings (OPEN, HASH, AUTH, etc.)

Usage:
    viewer = ScrollViewer(pager, "RECON RESULTS", lines)
    viewer.run()
"""

import time
from pagerctl import Pager

# ── Palette ───────────────────────────────────────────────────────────────────
C_BG      = Pager.rgb(0, 0, 20)
C_HEADER  = Pager.rgb(0, 180, 180)     # Cyan for viewer (distinct from main menu)
C_TEXT    = Pager.WHITE
C_HIT     = Pager.GREEN                # Highlight for notable lines
C_SECTION = Pager.YELLOW               # Section headers (=== ... ===)
C_DIM     = Pager.GRAY
C_STATUS  = Pager.rgb(10, 10, 10)

# ── Layout ────────────────────────────────────────────────────────────────────
HEADER_H  = 24
STATUS_H  = 18
FONT_SZ   = 2    # FONT_MEDIUM (2) = 10x14
LINE_H    = 22   # 14px glyph + 8px gap
LINES_Y   = HEADER_H + 2
LINES_MAX = (222 - HEADER_H - STATUS_H - 4) // LINE_H  # ~8 lines

# Keywords that cause a line to be highlighted green
_HIT_KEYWORDS = ("OPEN", "HASH", "AUTH", "SUCCESS", "CAPTURED", "CRED", "OK",
                  "CAMERA", "PRINTER", "AD", "ESXI", "HA")


def _line_color(line):
    upper = line.upper()
    if line.startswith("==="):
        return C_SECTION
    if any(k in upper for k in _HIT_KEYWORDS):
        return C_HIT
    return C_TEXT


class ScrollViewer:
    def __init__(self, pager, title, lines):
        """
        pager  : Pager instance
        title  : Header text
        lines  : list of strings to display
        """
        self.pager = pager
        self.title = title
        self.lines = lines
        self.offset = 0

    def _draw(self):
        p = self.pager
        p.clear(C_BG)

        # Header
        p.fill_rect(0, 0, 480, HEADER_H, C_HEADER)
        p.draw_text(6, 4, self.title[:40], Pager.BLACK, 2)

        # Lines
        visible = self.lines[self.offset: self.offset + LINES_MAX]
        for i, line in enumerate(visible):
            y = LINES_Y + i * LINE_H
            color = _line_color(line)
            p.draw_text(4, y + 2, str(line)[:38], color, FONT_SZ)

        # Scroll arrows
        if self.offset > 0:
            p.draw_text(468, LINES_Y, "^", C_DIM, 1)
        total = len(self.lines)
        if self.offset + LINES_MAX < total:
            p.draw_text(468, 222 - STATUS_H - 14, "v", C_DIM, 1)

        # Status bar with position indicator
        bar_y = 222 - STATUS_H
        p.fill_rect(0, bar_y, 480, STATUS_H, C_STATUS)
        end_line = min(self.offset + LINES_MAX, total)
        pos = f"{self.offset + 1}-{end_line}/{total}"
        p.draw_text(4, bar_y + 2, f"[UP/DN] SCROLL [B] BACK {pos}", C_DIM, 1)

        p.flip()

    def run(self):
        """Blocking scroll loop. A=scroll down, B=return."""
        p = self.pager
        p.clear_input_events()
        self._draw()

        while True:
            event = p.get_input_event()
            if not event:
                time.sleep(0.03)
                continue

            btn, etype, _ = event
            if etype != Pager.EVENT_PRESS:
                continue

            if btn == Pager.BTN_DOWN:
                max_off = max(0, len(self.lines) - LINES_MAX)
                self.offset = min(self.offset + 1, max_off)
                p.beep(600, 20)
                self._draw()

            elif btn == Pager.BTN_UP:
                self.offset = max(0, self.offset - 1)
                p.beep(600, 20)
                self._draw()

            elif btn == Pager.BTN_B:
                p.beep(400, 40)
                return
