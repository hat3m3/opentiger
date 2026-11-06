"""Readable result reports; the underlying JSON remains untouched."""
import re
import socket
import ssl
import textwrap
import urllib.error

from . import terminal as ui


def clean(value):
    text = ui.ANSI.sub('', str(value))
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', '', text)


def label(value):
    names = {'sha256': 'SHA-256', 'ttl': 'TTL (seconds)', 'ip': 'IP address',
             'resolved_ip': 'Resolved IP', 'hostname': 'Hostname', 'certificate_verified': 'Certificate verified',
             'conventional_service': 'Service hint', 'bytes': 'File size (bytes)', 'text_truncated': 'Shortened',
             'extension_mime_guess': 'File type hint', 'first_32_bytes_hex': 'First bytes (hex)'}
    return names.get(value, clean(value).replace('_', ' ').capitalize())


def scalar(value):
    if value is None:
        return 'Not provided'
    if isinstance(value, bool):
        return 'Yes' if value else 'No'
    text = clean(value)
    return {'unreachable_or_filtered': 'No reply / filtered', 'no_record': 'No record',
            'domain_not_found': 'Domain not found', 'lookup_failed': 'Lookup failed'}.get(text, text)


def wrapped(value, size):
    return textwrap.wrap(scalar(value), max(1, size), replace_whitespace=True) or ['']


def field(key, value, columns, color):
    key = label(key)
    space = min(23, max(10, columns // 3))
    if len(key) > space:
        print('  ' + ui.ink(key, 'muted', color))
        key = ''
    lines = wrapped(value, columns - space - 6)
    for index, line in enumerate(lines):
        prefix = key if index == 0 else ''
        print('  ' + ui.ink(prefix.ljust(space), 'muted', color) + '  ' + ui.ink(line, 'text', color))


def table(rows, columns, color):
    keys = list(dict.fromkeys(key for row in rows for key in row))
    if not keys:
        field('Results', 'No fields returned', columns, color)
        return
    # Wide records remain legible as fields rather than squeezed columns.
    if len(keys) > 4 or columns < 48:
        for index, row in enumerate(rows, 1):
            print('  ' + ui.ink(f'#{index:02}', 'accent', color))
            details(row, columns, color)
        return
    budget = columns - 4 - 3 * (len(keys) - 1)
    sizes = [max(len(label(key)), max((len(scalar(row.get(key, ''))) for row in rows), default=0)) for key in keys]
    while sum(sizes) > budget:
        biggest = max(range(len(sizes)), key=sizes.__getitem__)
        sizes[biggest] -= 1
    print('  ' + '   '.join(ui.ink(label(key).ljust(size), 'heading', color) for key, size in zip(keys, sizes)))
    print('  ' + ui.ink('   '.join('-' * size for size in sizes), 'line', color))
    for row in rows:
        cells = [wrapped(row.get(key, ''), size) for key, size in zip(keys, sizes)]
        for line in range(max(map(len, cells))):
            parts = []
            for key, size, cell in zip(keys, sizes, cells):
                value = cell[line] if line < len(cell) else ''
                role = 'text'
                if key == 'state' or key == 'status':
                    role = 'success' if value in ('open', 'ok') else 'muted'
                parts.append(ui.ink(value.ljust(size), role, color))
            print('  ' + '   '.join(parts))


def section(title, color):
    print('\n  ' + ui.ink('-- ', 'line', color) + ui.ink(label(title).upper(), 'heading', color))


def details(data, columns, color):
    for key, value in data.items():
        if key in ('note', 'explanation'):
            continue
        if isinstance(value, dict):
            section(key, color)
            details(value, columns, color)
        elif isinstance(value, (list, tuple)):
            if not value:
                field(key, 'No entries returned', columns, color)
                continue
            section(key, color)
            if all(isinstance(item, dict) and all(not isinstance(v, (dict, list, tuple)) for v in item.values()) for item in value):
                table(value, columns, color)
            else:
                for index, item in enumerate(value, 1):
                    if isinstance(item, dict):
                        print('  ' + ui.ink(f'#{index:02}', 'accent', color))
                        details(item, columns, color)
                    else:
                        display = ', '.join(map(scalar, item)) if isinstance(item, (list, tuple)) else scalar(item)
                        for part in wrapped(display, columns - 6):
                            print('  ' + ui.ink('| ', 'line', color) + ui.ink(part, 'text', color))
        else:
            field(key, value, columns, color)


def render_report(report, color=None, columns=None):
    from .catalog import MENU_TOOLS
    columns = max(36, columns or ui.width())
    data = dict(report['data'])
    name = dict((command, name) for name, command in MENU_TOOLS).get(report['tool'], report['tool'])
    print(ui.rule(name, color))
    field('Target', report['target'], columns, color)
    if report.get('workspace'):
        field('Workspace', report['workspace'], columns, color)
    if 'duration_seconds' in report:
        field('Time', f"{report['duration_seconds']:.2f}s", columns, color)
    print('  ' + ui.ink('-' * (columns - 4), 'line', color))
    if report['tool'] == 'overview' and 'summary' in data:
        field('Collection status', data.get('status'), columns, color)
        details(data['summary'], columns, color)
        for key in ('observations', 'potential_issues', 'lookup_errors'):
            section(key, color)
            if data.get(key):
                table(data[key], columns, color)
            else:
                print('  ' + ui.ink('None observed.', 'muted', color))
        section('Collection steps', color)
        table([{'check': key, 'status': value['status'],
                'details': value.get('error', value.get('reason', f"{value.get('duration_seconds', 0):.2f}s"))}
               for key, value in data.get('checks', {}).items()], columns, color)
        print()
        for part in wrapped(data.get('note', ''), columns - 6):
            print('  ' + ui.ink('| ' + part, 'muted', color))
        print()
        return
    if report['tool'] in ('ports', 'port-scan'):
        results = data.get('results', [])
        opened = sum(item['state'] == 'open' for item in results)
        field('Summary', f'{opened} open / {len(results)} ports checked', columns, color)
    elif report['tool'] == 'dns-records':
        records = data.pop('records', {})
        details(data, columns, color)
        section('DNS records', color)
        table([{'type': kind, 'status': item['status'], 'value': ', '.join(item.get('values', [])) or item.get('error', 'No record'),
                'ttl': item.get('ttl', '-')} for kind, item in records.items()], columns, color)
        data = {}
    elif report['tool'] == 'tls':
        for key in ('issuer', 'subject'):
            if data.get(key):
                data[key] = ', '.join(f'{name}={value}' for group in data[key] for name, value in group)
    if report['tool'] == 'http' and 'header_review' in data:
        data['header_review'] = [{'header': key, 'present': item['present'], 'purpose': item['meaning']}
                                 for key, item in data['header_review'].items()]
    details(data, columns, color)
    note = report['data'].get('note') or report['data'].get('explanation')
    if note:
        print()
        for part in wrapped(note, columns - 6):
            print('  ' + ui.ink('| ' + part, 'muted', color))
    print()


def error_report(error, target=None, color=None):
    cause = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(cause, ssl.SSLCertVerificationError):
        title, hint = 'Certificate verification failed', 'Check the target certificate and your local CA trust store.'
    elif isinstance(cause, (TimeoutError, socket.timeout)):
        title, hint = 'The request timed out', 'Check connectivity or retry with a longer --timeout.'
    elif isinstance(cause, socket.gaierror):
        title, hint = 'Hostname could not be resolved', 'Check the spelling and your DNS connection.'
    elif isinstance(cause, FileExistsError):
        title, hint = 'Report file already exists', 'Choose a new output filename; the existing file was preserved.'
    elif isinstance(cause, FileNotFoundError):
        title, hint = 'File not found', 'Check the path and quote paths containing spaces.'
    elif isinstance(cause, PermissionError):
        title, hint = 'Access denied', 'Choose a file or output folder your account can access.'
    else:
        title, hint = 'Could not complete this operation', 'Review the details below and check your input or connection.'
    print(ui.rule('Request failed', color))
    field('Problem', title, ui.width(), color)
    if target:
        field('Target', target, ui.width(), color)
    field('Details', str(error), ui.width(), color)
    field('Next step', hint, ui.width(), color)
    print()
