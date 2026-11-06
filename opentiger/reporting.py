"""Portable HTML exports and semantic comparisons for JSON reports."""
from html import escape
import json
from pathlib import Path
import urllib.parse

IGNORED_KEYS = {'ttl', 'duration_seconds', 'started_at', 'elapsed_seconds', 'milliseconds', 'days_remaining', 'date'}


def normalize(value):
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items() if key not in IGNORED_KEYS}
    if isinstance(value, (list, tuple)):
        return sorted((normalize(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


def compare_reports(before, after):
    if before.get('tool') != after.get('tool'):
        raise ValueError('Compare reports produced by the same tool.')
    if 'data' not in before or 'data' not in after:
        raise ValueError('Both files must be OpenTiger reports containing data.')
    changes = []

    def walk(old, new, path='data'):
        if isinstance(old, dict) and isinstance(new, dict):
            for key in sorted(old.keys() | new.keys()):
                if key not in old:
                    changes.append({'change': 'added', 'field': path + '.' + key, 'before': None, 'after': new[key]})
                elif key not in new:
                    changes.append({'change': 'removed', 'field': path + '.' + key, 'before': old[key], 'after': None})
                else:
                    walk(old[key], new[key], path + '.' + key)
        elif old != new:
            changes.append({'change': 'changed', 'field': path, 'before': old, 'after': new})

    walk(normalize(before['data']), normalize(after['data']))
    return {'schema_version': 1, 'tool': 'compare', 'target': after.get('target', ''),
            'data': {'source_tool': after.get('tool'), 'same_target': before.get('target') == after.get('target'),
                     'change_count': len(changes), 'changes': changes,
                     'note': 'Compares data fields. Collection time, durations, DNS TTLs, countdowns, and list order are ignored. Different targets require careful interpretation.'}}


def html_value(value):
    if isinstance(value, dict):
        return '<dl>' + ''.join('<dt>' + escape(str(key).replace('_', ' ')) + '</dt><dd>' + html_value(item) + '</dd>'
                               for key, item in value.items()) + '</dl>'
    if isinstance(value, (list, tuple)):
        if not value:
            return '<span class="muted">None returned</span>'
        if all(isinstance(item, dict) for item in value):
            keys = list(dict.fromkeys(key for item in value for key in item))
            return ('<div class="table-wrap"><table><thead><tr>'
                    + ''.join('<th>' + escape(str(key).replace('_', ' ')) + '</th>' for key in keys)
                    + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + html_value(item.get(key)) + '</td>' for key in keys)
                                                      + '</tr>' for item in value) + '</tbody></table></div>')
        return '<ul>' + ''.join('<li>' + html_value(item) + '</li>' for item in value) + '</ul>'
    if value is None:
        return '<span class="muted">Not provided</span>'
    text = str(value) if not isinstance(value, bool) else ('Yes' if value else 'No')
    try:
        parsed = urllib.parse.urlsplit(text) if text.startswith(('http://', 'https://')) else None
    except ValueError:
        parsed = None
    if parsed and parsed.netloc and not any(char.isspace() for char in text):
        return '<a rel="noreferrer" href="' + escape(text, quote=True) + '">' + escape(text) + '</a>'
    return '<span class="value">' + escape(text) + '</span>'


def export_html(report, destination):
    from .catalog import MENU_TOOLS
    title = dict((command, name) for name, command in MENU_TOOLS).get(report['tool'], report['tool'].replace('-', ' ').title())
    data = report.get('data', {})
    summary = data.get('summary', {})
    cards = ''.join('<article><b>' + escape(str(value)) + '</b><span>' + escape(key.replace('_', ' ')) + '</span></article>'
                    for key, value in summary.items() if isinstance(value, (str, int, float)))
    sections = ''.join('<section><h2>' + escape(key.replace('_', ' ').title()) + '</h2>'
                       + ('<details><summary>Expand collected evidence</summary>' + html_value(value) + '</details>' if key == 'checks' else html_value(value)) + '</section>'
                       for key, value in data.items() if key not in ('summary', 'status', 'elapsed_seconds', 'note', 'explanation'))
    collection = ('<span class="badge">Collection: ' + escape(str(data['status'])) + '</span>') if 'status' in data else ''
    workspace = ('<span class="badge">Workspace: ' + escape(str(report['workspace'])) + '</span>') if report.get('workspace') else ''
    note = data.get('note') or data.get('explanation')
    note_html = '<aside>' + escape(str(note)) + '</aside>' if note else ''
    css = '''
    :root{color-scheme:dark;--bg:#10100d;--panel:#1b1912;--line:#433724;--text:#eee6d4;--muted:#b2a58b;--yellow:#ffdb55}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,sans-serif}
    main{max-width:1120px;margin:auto;padding:48px 24px}header{border-bottom:1px solid var(--line);padding-bottom:26px}
    .brand{color:var(--yellow);font:700 14px monospace;letter-spacing:4px}.eyebrow{color:var(--muted);font:13px monospace}
    h1{font-size:clamp(30px,5vw,48px);line-height:1.1;margin:16px 0}h2{font-size:18px;color:var(--yellow);margin:0 0 18px}
    .badge{display:inline-block;border:1px solid var(--line);border-radius:5px;padding:3px 9px;margin:10px 8px 0 0;color:var(--muted);font:12px monospace}aside{padding:20px 0;color:var(--muted);font-size:13px}
    .target{font-family:monospace;overflow-wrap:anywhere}.meta,.muted,footer{color:var(--muted)}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}
    article{flex:1;min-width:140px;background:var(--panel);border:1px solid var(--line);padding:20px;border-radius:10px}article b{display:block;font-size:27px;color:var(--yellow)}article span{text-transform:capitalize;color:var(--muted)}
    section{padding:24px;background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-top:18px}
    dl{display:grid;grid-template-columns:minmax(110px,180px) minmax(0,1fr);gap:12px 20px;margin:0}dt{color:var(--muted);text-transform:capitalize}dd{margin:0;min-width:0}
    a{color:#ffd968;text-decoration-color:#6f5830;overflow-wrap:anywhere}.value{white-space:pre-wrap;overflow-wrap:anywhere}ul{margin:0;padding-left:20px}
    .table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left;font-size:14px}td,th{padding:12px;border-bottom:1px solid var(--line);vertical-align:top;min-width:100px;max-width:480px}th{text-transform:capitalize;color:var(--muted)}
    footer{margin-top:28px;font-size:12px}@media(max-width:640px){dl{display:block}dd{margin-bottom:14px}section{padding:16px}}
    @media print{body{background:white;color:#171717}main{padding:0}section,article{background:white;border-color:#aaa;break-inside:avoid}h2,.brand,article b,a{color:#6d4400}.muted,.meta,dt,th,footer{color:#555}}
    '''
    document = ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
                '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
                '<title>OpenTiger — ' + escape(title) + '</title><style>' + css + '</style></head><body><main><header>'
                '<div class="brand">OPENTIGER / REPORT</div><h1>' + escape(title) + '</h1><div class="target">' + escape(str(report.get('target', '')))
                + '</div><p class="meta">Collected ' + escape(str(report.get('started_at', 'not recorded'))) + ' · '
                + escape(str(report.get('duration_seconds', '—'))) + ' seconds</p>' + collection + workspace + '</header><div class="cards">' + cards + '</div>'
                + sections + note_html + '<footer>OpenTiger 0.1.0 · Observations are not proof of security or identity. This report contains no scripts or remote assets.</footer></main></body></html>')
    with Path(destination).expanduser().open('x', encoding='utf-8') as stream:
        stream.write(document)
    return Path(destination)
