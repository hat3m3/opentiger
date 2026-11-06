"""ASCII terminal components with optional ANSI color and no external dependencies."""
import os
import re
import shutil
import sys

TOKENS = {
    'accent': '38;2;255;214;70',
    'heading': '1;38;2;255;153;49',
    'text': '38;2;239;231;215',
    'muted': '38;2;170;155;133',
    'line': '38;2;112;79;42',
    'success': '38;2;130;222;163',
    'error': '38;2;255;128;147',
}
ANSI = re.compile(r'\x1b\[[0-9;]*m')
GLYPHS = {
    'O': ('  ___  ', ' / _ \\ ', '| | | |', '| |_| |', ' \\___/ '),
    'P': (' ____  ', '|  _ \\ ', '| |_) |', '|  __/ ', '|_|    '),
    'E': (' _____ ', '| ____|', '|  _|  ', '| |___ ', '|_____|'),
    'N': (' _   _ ', '| \\ | |', '|  \\| |', '| |\\  |', '|_| \\_|'),
    'T': (' _____ ', '|_   _|', '  | |  ', '  | |  ', '  |_|  '),
    'I': (' ___ ', '|_ _|', ' | | ', ' | | ', '|___|'),
    'G': ('  ____ ', ' / ___|', '| |  _ ', '| |_| |', ' \\____|'),
    'R': (' ____  ', '|  _ \\ ', '| |_) |', '|  _ < ', '|_| \\_\\'),
}


def supports_color():
    return sys.stdout.isatty() and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb'


def enable_ansi():
    if os.name == 'nt' and supports_color():
        import ctypes
        kernel = ctypes.windll.kernel32
        handle = kernel.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel.SetConsoleMode(handle, mode.value | 4)


def ink(value, role='text', color=None):
    enabled = supports_color() if color is None else color
    return f'\033[{TOKENS.get(role, role)}m{value}\033[0m' if enabled else str(value)


def gradient(value, color=None):
    enabled = supports_color() if color is None else color
    if not enabled:
        return value
    start, end = (255, 231, 95), (255, 116, 24)
    result = []
    for index, char in enumerate(value):
        fraction = index / max(1, len(value) - 1)
        rgb = [round(a + (b - a) * fraction) for a, b in zip(start, end)]
        result.append(f'\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m{char}')
    return ''.join(result) + '\033[0m'


def width():
    return max(20, min(146, shutil.get_terminal_size((100, 30)).columns - 2))


def header(columns=None, color=None):
    columns = columns or width()
    lines = ['']
    if columns >= 144:
        from .art import YELLOW_BANNER
        enabled = supports_color() if color is None else color
        lines.extend((YELLOW_BANNER if enabled else ANSI.sub('', YELLOW_BANNER)).splitlines())
    elif columns >= 74:
        for row in range(5):
            word = ' '.join(GLYPHS[letter][row] for letter in 'OPENTIGER')
            lines.append('  ' + gradient(word.rstrip(), color))
    else:
        lines.append('  ' + gradient('// OPENTIGER', color))
    lines.append('')
    subtitle = 'RECON / OSINT / UTILITIES'
    meta = 'v0.1.0'
    gap = max(1, columns - len(subtitle) - len(meta) - 4)
    if columns >= 38:
        lines.append('  ' + ink(subtitle, 'muted', color) + ' ' * gap + ink(meta, 'accent', color))
    else:
        lines.append('  ' + ink('RECON / OSINT', 'muted', color))
    lines.append('  ' + ink('-' * max(1, columns - 4), 'line', color))
    return '\n'.join(lines)


def rule(label, color=None):
    return '\n  ' + ink('// ', 'accent', color) + ink(label.upper(), 'heading', color) + '\n'


def prompt(label='console', hint=None):
    if hint:
        print('  ' + ink(hint, 'muted'))
    print('  ' + ink('.-- ', 'line') + ink('opentiger', 'heading')
          + ink(' / ', 'line') + ink(label, 'muted'))
    return input('  ' + ink("'--", 'line') + ink('> ', 'accent'))


def message(text, state='info'):
    role, marker = {'info': ('accent', '*'), 'success': ('success', '+'),
                    'error': ('error', '!')}.get(state, ('accent', '*'))
    return '  ' + ink(f'[{marker}] ', role) + ink(text, 'text')


def dashboard(columns=None, color=None):
    from .catalog import MENU_TOOLS, MENU_GROUPS
    columns = columns or width()
    names = {index: name for index, (name, _) in enumerate(MENU_TOOLS, 1)}
    count = min(4, max(1, columns // 36))
    cell = (columns - 2 - (count - 1) * 2) // count
    entries = [(title, [(number, names[number]) for number in numbers])
               for title, numbers in MENU_GROUPS]
    output = ['']

    def border(left, fill, right):
        return ink(left + fill * (cell - 2) + right, 'line', color)

    for offset in range(0, len(entries), count):
        block = entries[offset:offset + count]
        output.append('  ' + '  '.join(border('.', '-', '.') for _ in block))
        titles = []
        for title, items in block:
            title = title[:max(1, cell - 11)]
            padding = ' ' * max(1, cell - len(title) - 6)
            titles.append(ink('| ', 'line', color) + gradient(title, color) + padding
                          + ink(f'{len(items):02}', 'muted', color) + ink(' |', 'line', color))
        output.append('  ' + '  '.join(titles))
        output.append('  ' + '  '.join(border('|', '-', '|') for _ in block))
        for row in range(max(len(items) for _, items in block)):
            cells = []
            for _, items in block:
                if row >= len(items):
                    cells.append(ink('|', 'line', color) + ' ' * (cell - 2) + ink('|', 'line', color))
                    continue
                number, name = items[row]
                available = max(1, cell - 9)
                name = name if len(name) <= available else name[:max(0, available - 1)] + '~'
                plain = f'[{number:02}] {name}'
                cells.append(ink('| ', 'line', color) + ink(f'[{number:02}]', 'accent', color)
                             + ' ' + ink(name, 'text', color) + ' ' * max(0, cell - 3 - len(plain))
                             + ink('|', 'line', color))
            output.append('  ' + '  '.join(cells))
        output.append('  ' + '  '.join(border("'", '-', "'") for _ in block))
        output.append('')
    actions = ''
    for key, name in (('W', 'Workspace'), ('R', 'Recent'), ('F', 'Favorites'), ('D', 'Diagnostics'), ('I', 'Install'), ('H', 'Help'), ('Q', 'Quit')):
        action = ink(f'[{key}]', 'accent', color) + ink(' ' + name, 'muted', color)
        if actions and len(ANSI.sub('', actions)) + len(ANSI.sub('', action)) + 2 > columns - 2:
            output.append('  ' + actions)
            actions = ''
        actions += ('  ' if actions else '') + action
    hint = f'Select [01-{len(MENU_TOOLS)}] or type a tool name'
    gap = columns - 2 - len(ANSI.sub('', actions)) - len(hint)
    if gap >= 4:
        output.append('  ' + actions + ' ' * gap + ink(hint, 'muted', color))
    else:
        output.extend(['  ' + actions, '  ' + ink(hint, 'muted', color)])
    output.append('')
    return '\n'.join(output)
