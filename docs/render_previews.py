"""Render current ANSI output into README images. Run from the project root."""
import io
import os
from contextlib import redirect_stdout
from pathlib import Path
import re
import sys
from unittest.mock import patch

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from opentiger import terminal as ui
from opentiger.cli import execute
from opentiger.results import render_report

ASSETS = ROOT / 'docs' / 'assets'
ASSETS.mkdir(exist_ok=True)
BACKGROUND = '#0e0d0a'
BASE = (239, 231, 215)
PALETTE = [(0, 0, 0), (170, 0, 0), (0, 170, 0), (170, 110, 0),
           (0, 0, 170), (170, 0, 170), (0, 170, 170), (190, 190, 190),
           (105, 105, 105), (255, 100, 100), (120, 230, 160), (255, 220, 70),
           (120, 150, 255), (230, 140, 255), (100, 235, 235), (255, 255, 255)]
FONT_PATHS = [Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Fonts/consola.ttf',
              Path('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf')]
FONT_PATH = next((path for path in FONT_PATHS if path.exists()), None)
FONT = ImageFont.truetype(str(FONT_PATH), 18) if FONT_PATH else ImageFont.load_default(size=18)


def render(text, filename, title):
    rows = text.strip('\n').splitlines()
    cell, line = FONT.getlength('M'), 26
    length = max(len(ui.ANSI.sub('', row)) for row in rows)
    width = max(900, round(length * cell) + 64)
    height = len(rows) * line + 104
    canvas = Image.new('RGB', (width, height), '#17140f')
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle((1, 1, width - 2, height - 2), radius=14, fill=BACKGROUND, outline='#46331c', width=1)
    draw.line((1, 49, width - 2, 49), fill='#34291b')
    for x, color in ((27, '#fc9851'), (49, '#f8cb54'), (71, '#8b8065')):
        draw.ellipse((x, 20, x + 9, 29), fill=color)
    draw.text((102, 12), title, font=FONT, fill='#bfae90')
    fg, bg = BASE, None
    for y, row in enumerate(rows):
        x = 24
        for token in re.split(r'(\x1b\[[0-9;]*m)', row):
            if token.startswith('\x1b['):
                codes = [int(item or 0) for item in token[2:-1].split(';')]
                i = 0
                while i < len(codes):
                    code = codes[i]
                    if code == 0:
                        fg, bg = BASE, None
                    elif code in (38, 48) and codes[i + 1:i + 2] == [2] and i + 4 < len(codes):
                        rgb = tuple(codes[i + 2:i + 5])
                        if code == 38: fg = rgb
                        else: bg = rgb
                        i += 4
                    elif 30 <= code <= 37: fg = PALETTE[code - 30]
                    elif 90 <= code <= 97: fg = PALETTE[code - 90 + 8]
                    elif 40 <= code <= 47: bg = PALETTE[code - 40]
                    elif 100 <= code <= 107: bg = PALETTE[code - 100 + 8]
                    elif code == 39: fg = BASE
                    elif code == 49: bg = None
                    i += 1
                continue
            size = FONT.getlength(token)
            if bg and token:
                draw.rectangle((x, 68 + y * line, x + size, 68 + y * line + line), fill=bg)
            draw.text((x, 65 + y * line), token, font=FONT, fill=fg)
            x += size
    canvas.save(ASSETS / filename, optimize=True)
    print(f'{filename}: {width} x {height}')


def main():
    capture = io.StringIO()
    with patch('opentiger.terminal.supports_color', return_value=True), redirect_stdout(capture):
        print(ui.header(146, True))
        print(ui.dashboard(146, True))
        with patch('builtins.input', return_value=''):
            ui.prompt()
    # input() writes its prompt itself; mocked input does not, so add that final prompt.
    render(capture.getvalue() + '  ' + ui.ink("'--", 'line', True) + ui.ink('> _', 'accent', True),
           'terminal-home.png', 'OpenTiger  /  console')
    report = execute('dns', 'localhost')
    capture = io.StringIO()
    with redirect_stdout(capture):
        render_report(report, color=True, columns=92)
    render(capture.getvalue(), 'terminal-result.png', 'OpenTiger  /  DNS lookup  /  localhost')


if __name__ == '__main__':
    main()
