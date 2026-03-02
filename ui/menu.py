"""
menu.py - pagerctl LCD menu system for PagerPwn

Layout (480x222 landscape):
  [0..21]   Header bar (magenta)
  [22..201] Menu items (scrollable, ~8 visible)
  [202..221] Status bar (hint text)

Controls:
  UP / DOWN = move cursor
  A (green) = select / execute
  B (red)   = back / abort (hold 1.5s during module run)
"""

import time
import threading
from pagerctl import Pager

# ── Palette ──────────────────────────────────────────────────────────────────
C_BG      = Pager.rgb(0, 0, 20)
C_HEADER  = Pager.rgb(180, 0, 180)    # Magenta
C_SELECT  = Pager.rgb(0, 180, 180)    # Cyan
C_TEXT    = Pager.WHITE
C_DIM     = Pager.GRAY
C_HIT     = Pager.RED
C_STATUS  = Pager.rgb(10, 10, 10)

# ── Layout ────────────────────────────────────────────────────────────────────
HEADER_H  = 24
STATUS_H  = 20
ITEM_H    = 28
ITEMS_Y   = HEADER_H + 2
# Number of items visible without scrolling
ITEMS_MAX = (222 - HEADER_H - STATUS_H - 4) // ITEM_H  # = 6

# Hold B for this long (ms) to abort / go back
HOLD_B_MS = 1500


class Menu:
    def __init__(self, pager, title, items):
        """
        pager  : Pager instance (already init'd)
        title  : string shown in header
        items  : list of (label: str, callback: callable | None)
                 callback signature: callback(config, ui_callback, stop_event) -> any
        """
        self.pager = pager
        self.title = title
        self.items = list(items)  # mutable copy
        self.cursor = 0
        self.scroll_offset = 0
        self._stop_event = threading.Event()

    # ── LEDs ─────────────────────────────────────────────────────────────────

    def _led_idle(self):
        self.pager.led_all_off()

    def _led_running(self):
        # b-button-led = green A button LED (names swapped on hardware)
        self.pager.led_set("b-button-led", 180)
        self.pager.led_set("a-button-led", 0)

    def _led_hit(self):
        """Flash red LED 3×."""
        p = self.pager
        for _ in range(3):
            p.led_set("a-button-led", 255)   # a-button-led = red B LED
            time.sleep(0.1)
            p.led_set("a-button-led", 0)
            time.sleep(0.1)

    # ── Drawing ───────────────────────────────────────────────────────────────

    def _draw_header(self, label=None):
        p = self.pager
        p.fill_rect(0, 0, 480, HEADER_H, C_HEADER)
        p.draw_text(6, 4, label or self.title, Pager.BLACK, 2)

    def _draw_menu(self):
        p = self.pager
        p.clear(C_BG)
        self._draw_header()

        visible = self.items[self.scroll_offset: self.scroll_offset + ITEMS_MAX]
        for i, (label, _) in enumerate(visible):
            idx = i + self.scroll_offset
            y = ITEMS_Y + i * ITEM_H
            if idx == self.cursor:
                p.fill_rect(0, y, 480, ITEM_H, C_SELECT)
                p.draw_text(8, y + 5, f"> {label}"[:38], Pager.BLACK, 2)
            else:
                p.draw_text(8, y + 5, f"  {label}"[:38], C_TEXT, 2)

        # Scroll arrows
        if self.scroll_offset > 0:
            p.draw_text(468, ITEMS_Y, "^", C_DIM, 1)
        if self.scroll_offset + ITEMS_MAX < len(self.items):
            p.draw_text(468, ITEMS_Y + ITEMS_MAX * ITEM_H - 12, "v", C_DIM, 1)

        # Status bar
        bar_y = 222 - STATUS_H
        p.fill_rect(0, bar_y, 480, STATUS_H, C_STATUS)
        p.draw_text(4, bar_y + 3, "[UP/DN] MOVE  [A] SELECT  [BB] EXIT", C_DIM, 1)

        p.flip()

    def _draw_status(self, line1, line2=""):
        """Module-running display. Called by ui_callback from running module."""
        p = self.pager
        p.clear(C_BG)
        self._draw_header()

        p.draw_text_centered(70, line1[:30], C_SELECT, 2)
        if line2:
            p.draw_text_centered(110, line2[:36], C_TEXT, 2)

        bar_y = 222 - STATUS_H
        p.fill_rect(0, bar_y, 480, STATUS_H, C_STATUS)
        p.draw_text(4, bar_y + 3, "[B-HOLD] ABORT", C_DIM, 1)

        p.flip()

    def draw_trophy(self, line1, line2="", line3=""):
        """
        Full-screen capture notification.
        Flashes red LED, plays a victory tone, waits for B press.
        """
        p = self.pager
        p.clear(C_BG)
        p.fill_rect(0, 0, 480, HEADER_H, C_HIT)
        p.draw_text_centered(4, "*** CAPTURED ***", Pager.BLACK, 2)

        p.draw_text_centered(60, line1[:30], C_HIT, 2)
        if line2:
            p.draw_text_centered(95, line2[:36], C_TEXT, 2)
        if line3:
            p.draw_text_centered(125, line3[:36], C_DIM, 1)

        p.draw_text_centered(165, "[A] CONTINUE", C_SELECT, 2)
        p.flip()

        self._led_hit()
        p.beep(880, 100)
        p.beep(1108, 100)
        p.beep(1320, 200)
        p.vibrate(150)

        # Wait for A (green) to continue
        p.clear_input_events()
        while True:
            event = p.get_input_event()
            if event:
                btn, etype, _ = event
                if btn == Pager.BTN_A and etype == Pager.EVENT_PRESS:
                    break
            time.sleep(0.05)

        self._led_idle()

    # ── Module runner ─────────────────────────────────────────────────────────

    def run_module(self, callback, config):
        """
        Run a module callback in the foreground.
        The ui_callback wires to _draw_status so the module can update LCD.
        B held for HOLD_B_MS → sets stop_event to abort the module.
        """
        self._stop_event.clear()
        self._led_running()
        p = self.pager

        def ui_cb(line1, line2=""):
            self._draw_status(line1, line2)

        # Background thread watches for B-hold abort
        def _input_monitor():
            press_t = None
            while not self._stop_event.is_set():
                event = p.get_input_event()
                if event:
                    btn, etype, _ = event
                    if btn == Pager.BTN_B:
                        if etype == Pager.EVENT_PRESS:
                            press_t = time.time()
                        elif etype == Pager.EVENT_RELEASE:
                            press_t = None
                if press_t and (time.time() - press_t) * 1000 >= HOLD_B_MS:
                    self._stop_event.set()
                    ui_cb("ABORTED", "Hold B released")
                    break
                time.sleep(0.05)

        monitor = threading.Thread(target=_input_monitor, daemon=True)
        monitor.start()

        result = None
        try:
            result = callback(config, ui_cb, self._stop_event)
        except Exception as e:
            ui_cb("ERROR", str(e)[:40])
            time.sleep(2)

        self._stop_event.set()
        monitor.join(timeout=1)
        self._led_idle()
        return result

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _do_exit(self, config):
        """Shared exit sequence."""
        p = self.pager
        p.clear(C_BG)
        p.draw_text_centered(85, "Goodbye.", C_DIM, 4)
        p.flip()
        p.beep(523, 100)
        p.beep(392, 100)
        p.beep(262, 200)
        time.sleep(0.8)

    def run(self, config):
        """
        Blocking main menu loop. Returns when EXIT is selected.
        Handles QUIET MODE toggle inline.
        B hold (1.5s) or double-tap B exits from main menu.
        """
        p = self.pager
        p.clear_input_events()
        self._draw_menu()

        b_press_time = None     # tracks B hold
        b_last_tap = 0          # tracks double-tap
        DOUBLE_TAP_MS = 400

        while True:
            event = p.get_input_event()

            # Check B hold while waiting for events
            if b_press_time and (time.time() - b_press_time) * 1000 >= HOLD_B_MS:
                self._do_exit(config)
                return

            if not event:
                time.sleep(0.02)
                continue

            btn, etype, _ = event

            # Track B hold and double-tap across all event types
            if btn == Pager.BTN_B:
                if etype == Pager.EVENT_PRESS:
                    now = time.time()
                    # Double-tap check
                    if (now - b_last_tap) * 1000 <= DOUBLE_TAP_MS:
                        self._do_exit(config)
                        return
                    b_last_tap = now
                    b_press_time = now
                elif etype == Pager.EVENT_RELEASE:
                    b_press_time = None
                continue

            if etype != Pager.EVENT_PRESS:
                continue

            if btn == Pager.BTN_UP:
                self.cursor = (self.cursor - 1) % len(self.items)
                if self.cursor < self.scroll_offset:
                    self.scroll_offset = self.cursor
                elif self.cursor >= self.scroll_offset + ITEMS_MAX:
                    self.scroll_offset = self.cursor - ITEMS_MAX + 1
                p.beep(600, 25)
                self._draw_menu()

            elif btn == Pager.BTN_DOWN:
                self.cursor = (self.cursor + 1) % len(self.items)
                if self.cursor >= self.scroll_offset + ITEMS_MAX:
                    self.scroll_offset = self.cursor - ITEMS_MAX + 1
                elif self.cursor < self.scroll_offset:
                    self.scroll_offset = self.cursor
                p.beep(600, 25)
                self._draw_menu()

            elif btn == Pager.BTN_A:
                # SELECT
                label, callback = self.items[self.cursor]

                if label.startswith("QUIET MODE"):
                    new_state = not config.get("QUIET_MODE", False)
                    config["QUIET_MODE"] = new_state
                    self.items[self.cursor] = (
                        f"QUIET MODE [{'ON ' if new_state else 'OFF'}]",
                        callback,
                    )
                    p.beep(400 if new_state else 800, 80)
                    self._draw_menu()

                elif label == "EXIT":
                    self._do_exit(config)
                    return

                elif callback is not None:
                    p.beep(800, 40)
                    p.clear_input_events()
                    self.run_module(callback, config)
                    p.clear_input_events()
                    self._draw_menu()

