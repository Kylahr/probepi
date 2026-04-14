"""Waveshare 2.13" B/W e-ink display renderer (250x122).

Uses partial refresh on a schedule to avoid wearing out the panel.
"""
import time
from PIL import Image, ImageDraw, ImageFont

try:
    from waveshare_epd import epd2in13_V4 as epd_driver
except Exception:
    try:
        from waveshare_epd import epd2in13_V3 as epd_driver
    except Exception:
        from waveshare_epd import epd2in13_V2 as epd_driver


WIDTH = 250
HEIGHT = 122


def _load_font(size):
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    return ImageFont.load_default()


class EinkDisplay:
    def __init__(self):
        self.epd = epd_driver.EPD()
        self.epd.init()
        self.epd.Clear(0xFF)
        self.font_big = _load_font(18)
        self.font = _load_font(12)
        self.font_small = _load_font(10)
        self._last_full_refresh = 0
        self._partial_initialized = False

    def _canvas(self):
        img = Image.new("1", (WIDTH, HEIGHT), 255)
        return img, ImageDraw.Draw(img)

    def render(self, stats, recent_ssids, top_groups):
        img, draw = self._canvas()

        draw.rectangle((0, 0, WIDTH, 16), fill=0)
        draw.text((3, 0), "PROBE SNIFFER", font=self.font_big, fill=255)

        y = 20
        line1 = f"probes:{stats['probes']:<5} macs:{stats['macs']:<4}"
        line2 = f"devs:{stats['devices']:<5} ppl:{stats['groups']:<3} ssids:{stats['ssids']}"
        draw.text((2, y), line1, font=self.font, fill=0)
        draw.text((2, y + 14), line2, font=self.font, fill=0)

        y = 52
        draw.line((2, y, WIDTH - 2, y), fill=0)
        draw.text((2, y + 2), "recent SSIDs:", font=self.font_small, fill=0)
        y += 14
        for s in recent_ssids[:4]:
            label = s["ssid"][:30] if s["ssid"] else "<hidden>"
            draw.text((2, y), f"- {label}", font=self.font_small, fill=0)
            y += 11
            if y > HEIGHT - 12:
                break

        ts = time.strftime("%H:%M:%S")
        draw.text((WIDTH - 50, HEIGHT - 11), ts, font=self.font_small, fill=0)

        self._push(img)

    def _push(self, img):
        now = time.time()
        if not self._partial_initialized or now - self._last_full_refresh > 300:
            self.epd.init()
            self.epd.display(self.epd.getbuffer(img))
            self._last_full_refresh = now
            self._partial_initialized = True
            try:
                self.epd.init_part()
            except Exception:
                pass
        else:
            try:
                self.epd.displayPartial(self.epd.getbuffer(img))
            except Exception:
                self.epd.display(self.epd.getbuffer(img))

    def sleep(self):
        try:
            self.epd.sleep()
        except Exception:
            pass

    def message(self, text):
        img, draw = self._canvas()
        draw.text((4, 4), text, font=self.font, fill=0)
        self._push(img)
