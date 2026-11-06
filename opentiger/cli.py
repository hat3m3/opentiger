"""Terminal interface and machine-readable report envelopes."""
import argparse
import inspect
import ipaddress
import datetime
import json
from http.client import HTTPException
import re
import sys
import subprocess
import time
from contextlib import redirect_stdout
from pathlib import Path

from .tools import TOOLS as BASE_HANDLERS
from .extras import EXTRA_HANDLERS
from .catalog import MENU_TOOLS
from .workbench import HANDLERS

from . import terminal as ui
from .results import render_report, error_report
from .setup import install_requirements, environment_python
from . import workspaces
from .investigations import username_check, broken_links
from .reporting import export_html, compare_reports
from .diagnostics import diagnose
from .progress import Progress

TOOLS = {**BASE_HANDLERS, **EXTRA_HANDLERS, **HANDLERS, 'username': username_check, 'broken-links': broken_links}
DESCRIPTIONS = {command: name for name, command in MENU_TOOLS}
TARGET_HINTS = {
    'file': 'File path', 'file-text': 'File path', 'metadata': 'File path',
    'clean-image': 'PNG or JPEG path (a new copy is created)',
    'reverse-ip': 'IP address, e.g. 127.0.0.1', 'ip-info': 'IP address, e.g. 127.0.0.1',
    'hosts': 'Subnet with at most 64 addresses, e.g. 192.168.1.0/28',
    'email-domain': 'Domain or email address', 'email-info': 'Email address', 'email-search': 'Email address',
    'url-decode': 'URL or encoded text (offline)', 'search': 'Search query, e.g. site:example.com contact',
    'wallet': 'Bitcoin or 0x-prefixed EVM address', 'phone': 'Phone number with country code, e.g. +442083661177',
    'username': 'Username', 'profile': 'Instagram username', 'connection': 'Host or host:port, e.g. 127.0.0.1:8000',
}
WORKSPACE_TOOLS = {'overview', 'website-check', 'port-scan', 'crawl', 'connection', 'dns', 'rdap', 'http', 'tls', 'ports',
                   'dns-records', 'reverse-ip', 'email-domain', 'website-links', 'robots', 'broken-links', 'ip-info'}


class BackToMenu(Exception):
    """Cancel a tool's input without terminating the menu."""


def ask_value(command, hint):
    value = ui.prompt(command, hint + ' / type back to cancel').strip()
    if value.lower() in ('back', 'menu', 'cancel'):
        raise BackToMenu()
    return value


def workspace_default(tool, target):
    if tool in ('ip-info', 'reverse-ip'):
        from .tools import host
        try:
            return str(ipaddress.ip_address(host(target)))
        except ValueError:
            return None
    return target


def safe(value):
    # Remote data must never inject terminal control sequences.
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', '', str(value))


def banner():
    print(ui.header())


def execute(tool, target, timeout=8, port_spec=None, max_pages=None, max_links=None, include_external=False, progress=None):
    if not target.strip():
        raise ValueError("Enter a target or value.")
    if not 0 < timeout <= 60:
        raise ValueError("Timeout must be greater than zero and at most 60 seconds.")
    kwargs = {'timeout': timeout}
    if tool in ('ports', 'port-scan') and port_spec:
        kwargs['port_spec'] = port_spec
    if tool == 'crawl' and max_pages is not None:
        kwargs['max_pages'] = max_pages
    if tool == 'broken-links':
        if max_links is not None:
            kwargs['max_links'] = max_links
        kwargs['include_external'] = include_external
    if 'progress' in inspect.signature(TOOLS[tool]).parameters:
        kwargs['progress'] = progress
    if progress:
        progress(0, 1, DESCRIPTIONS.get(tool, tool))
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    clock = time.perf_counter()
    data = TOOLS[tool](target, **kwargs)
    return {'schema_version': 1, 'tool': tool, 'target': target, 'started_at': started,
            'duration_seconds': round(time.perf_counter() - clock, 4), 'data': data}


def menu_table(width=None):
    return ui.dashboard(width, color=False)


def menu():
    while True:
        if ui.supports_color():
            print('\033[2J\033[H', end='')
        banner()
        config = workspaces.settings()
        if config.get('active_workspace'):
            workspace = workspaces.get_workspace()
            print(ui.message(f"Workspace: {safe(workspace['name'])} / {safe(workspace['target'])}"))
        print(ui.dashboard())
        choice = ui.prompt().strip().lower()
        if choice in ('q', 'quit', 'exit'):
            return 0
        if choice in ('i', 'install'):
            code = install_requirements()
            input('\n  Enter to return > ')
            if code == 0 and Path(sys.executable).resolve() != environment_python().resolve():
                print(ui.message('Opening OpenTiger in the prepared environment...'))
                return subprocess.run([str(environment_python()), '-m', 'opentiger', 'menu'],
                                      cwd=Path(__file__).resolve().parents[1]).returncode
            continue
        if choice in ('h', 'help'):
            print('  Select a tool number or search by name. Every tool supports JSON and HTML export.')
            print('  Every tool has a direct command: opentiger --help')
            print('  Press I to install all requirements into the project .venv.')
            print('  Type back at a tool prompt to return to the menu.')
            print('  W: workspaces, R: recent targets, F: favorites, D: local diagnostics.')
            input('\n  Enter to return > ')
            continue
        if choice in ('v', 'version'):
            print('  OpenTiger 0.1.0')
            input('\n  Enter to return > ')
            continue
        if choice in ('w', 'r', 'f', 'd'):
            try:
                menu_shortcut(choice)
            except (OSError, ValueError) as error:
                error_report(error)
                input('  Enter to return > ')
            continue
        matches = [(index, name, command) for index, (name, command) in enumerate(MENU_TOOLS, 1)
                   if choice and (choice in name.lower() or choice in command)]
        if choice.isdigit() and 1 <= int(choice) <= len(MENU_TOOLS):
            interactive_tool(MENU_TOOLS[int(choice) - 1][1])
        elif choice in DESCRIPTIONS:
            interactive_tool(choice)
        elif len(matches) == 1:
            interactive_tool(matches[0][2])
        else:
            if matches:
                for index, name, _ in matches:
                    print(ui.message(f'[{index:02}] {name}'))
            else:
                print(ui.message('No matching tool. Enter a number or search term.', 'error'))
            selected = ui.prompt('select', 'Tool number / Enter returns').strip()
            if selected.isdigit() and 1 <= int(selected) <= len(MENU_TOOLS):
                interactive_tool(MENU_TOOLS[int(selected) - 1][1])


def interactive_tool(tool, default_target=None):
    print(ui.rule(DESCRIPTIONS[tool]))
    while True:
        try:
            workspace = None
            if tool in WORKSPACE_TOOLS and workspaces.settings().get('active_workspace'):
                workspace = workspaces.get_workspace()
            proposed = default_target or (workspace_default(tool, workspace['target']) if workspace else None)
            if default_target:
                workspace = None
            hint = TARGET_HINTS.get(tool, 'Domain, IP, or HTTP(S) URL, e.g. example.com')
            if proposed:
                hint += ' / Enter uses ' + proposed
            target = ask_value(tool, hint)
            if not target and proposed:
                target = proposed
            spec = None
            if tool in ('ports', 'port-scan'):
                spec = ask_value(tool, 'TCP ports [22,80,443]; Enter accepts defaults') or '22,80,443'
            with Progress(DESCRIPTIONS[tool]) as progress:
                report = execute(tool, target, port_spec=spec, progress=progress)
            workspaces.remember(target)
            if workspace:
                report['workspace'] = workspace['name']
                path = workspaces.record_run(workspace['name'], report)
                print(ui.message('Workspace run saved: ' + str(path), 'success'))
        except BackToMenu:
            return
        except (OSError, ValueError, KeyError, HTTPException) as error:
            error_report(error)
            continue
        render_report(report)
        while True:
            try:
                kind = ask_value('export', '[J] JSON / [H] HTML / [B] both / Enter skips').lower()
                if not kind:
                    break
                if kind not in ('j', 'h', 'b'):
                    raise ValueError('Choose J, H, B, or press Enter.')
                destination = ask_value('export', 'New output filename or base path')
                if not destination:
                    raise ValueError('Enter a new output filename.')
                base = Path(destination).expanduser()
                if kind in ('j', 'b'):
                    save(report, base if base.suffix.lower() == '.json' else Path(str(base) + '.json'))
                if kind in ('h', 'b'):
                    export_html(report, base if base.suffix.lower() == '.html' else Path(str(base) + '.html'))
                print(ui.message('Report exported.', 'success'))
                break
            except BackToMenu:
                return
            except (OSError, ValueError) as error:
                error_report(error)
        input('\n  Enter to return > ')
        return


def utility_report(tool, data, target='local'):
    return {'schema_version': 1, 'tool': tool, 'target': target,
            'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'data': data}


def menu_shortcut(choice):
    if choice == 'w':
        action = ui.prompt('workspace', '[C] Create / [U] Use / [L] List / [O] Off / Enter returns').lower().strip()
        if action == 'c':
            name = ui.prompt('workspace', 'New workspace name').strip()
            target = ui.prompt('workspace', 'Domain, IP, or URL').strip()
            workspaces.create_workspace(name, target)
            print(ui.message('Workspace created and selected.', 'success'))
        elif action == 'u':
            workspaces.activate(ui.prompt('workspace', 'Workspace name').strip())
        elif action == 'o':
            config = workspaces.settings()
            config['active_workspace'] = None
            workspaces.write_json(workspaces.home() / 'settings.json', config)
        elif action == 'l':
            render_report(utility_report('workspaces', {'workspaces': workspaces.list_workspaces()}))
        elif action:
            raise ValueError('Choose C, U, L, or O.')
    elif choice == 'r':
        recent = workspaces.settings().get('recent_targets', [])
        for index, target in enumerate(recent, 1):
            print(ui.message(f'[{index:02}] {safe(target)}'))
        selected = ui.prompt('recent', 'Target number to reuse / Enter returns').strip()
        if selected:
            if not selected.isdigit() or not 1 <= int(selected) <= len(recent):
                raise ValueError('Choose a listed recent target number.')
            command = ui.prompt('recent', 'Tool command, e.g. dns or overview').strip()
            if command not in DESCRIPTIONS:
                raise ValueError('Choose a command shown in opentiger --help.')
            interactive_tool(command, default_target=recent[int(selected) - 1])
    elif choice == 'f':
        config = workspaces.settings()
        for command in config.get('favorites', []):
            print(ui.message(command))
        value = ui.prompt('favorites', 'Command to run / +command adds / -command removes / Enter returns').strip()
        if value:
            if value.startswith(('+', '-')):
                workspaces.favorite(value[1:], 'remove' if value.startswith('-') else 'add')
            elif value in DESCRIPTIONS:
                interactive_tool(value)
            else:
                raise ValueError('Enter a tool command shown in opentiger --help.')
    elif choice == 'd':
        render_report(utility_report('diagnostics', diagnose()))
    input('\n  Enter to return > ')


def save(report, destination):
    # Exclusive creation protects existing notes and reports.
    with Path(destination).expanduser().open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, ensure_ascii=True)
        stream.write('\n')


def main(argv=None):
    ui.enable_ansi()
    parser = argparse.ArgumentParser(description='OpenTiger - reconnaissance, OSINT, and utilities.')
    parser.add_argument('--version', action='version', version='OpenTiger 0.1.0')
    commands = parser.add_subparsers(dest='command')
    commands.add_parser('menu', help='Open the interactive workbench')
    commands.add_parser('install', help='Install all requirements into the project .venv')
    diagnostics = commands.add_parser('diagnostics', help='Check dependencies, DNS, trust, and report storage')
    diagnostics.add_argument('--online', action='store_true', help='Also check verified HTTPS to example.com')
    diagnostics.add_argument('--timeout', type=float, default=5)
    compare = commands.add_parser('compare', help='Compare two JSON reports from the same tool')
    compare.add_argument('before')
    compare.add_argument('after')
    workspace_parser = commands.add_parser('workspace', help='Create, select, or inspect saved targets')
    workspace_parser.add_argument('action', nargs='?', default='list', choices=['create', 'use', 'list', 'show', 'history', 'off'])
    workspace_parser.add_argument('name', nargs='?')
    workspace_parser.add_argument('target', nargs='?')
    favorite_parser = commands.add_parser('favorite', help='Save frequently used commands')
    favorite_parser.add_argument('action', nargs='?', default='list', choices=['add', 'remove', 'list'])
    favorite_parser.add_argument('command_name', nargs='?')
    recent_parser = commands.add_parser('recent', help='Show recent targets')
    for utility in (diagnostics, compare, workspace_parser, favorite_parser, recent_parser):
        utility.add_argument('--json', action='store_true')
        utility.add_argument('--output', help='Save JSON to a new file')
        utility.add_argument('--html', help='Export a standalone HTML report')
    for name, description in DESCRIPTIONS.items():
        command = commands.add_parser(name, help=description)
        command.add_argument('target', nargs='?', help='Value to inspect; network tools can use an active workspace')
        command.add_argument('--json', action='store_true', help='Emit a JSON report without decoration')
        command.add_argument('--output', help='Save JSON to a new file')
        command.add_argument('--html', help='Export a standalone HTML report')
        command.add_argument('--workspace', help='Use this workspace target and save run history')
        command.add_argument('--timeout', type=float, default=8, help='Network operation timeout in seconds (0–60, exclusive of 0)')
        if name in ('ports', 'port-scan'):
            command.add_argument('--ports', default='22,53,80,443,445,3389,8000,8080,8443')
        if name == 'crawl':
            command.add_argument('--pages', type=int, default=10, help='Page limit from 1 to 30')
        if name == 'broken-links':
            command.add_argument('--max-links', type=int, default=20, help='Maximum 1-50 links to check')
            command.add_argument('--include-external', action='store_true', help='Also check links and redirects outside the source origin')
    args = parser.parse_args(argv)
    try:
        if args.command == 'install':
            return install_requirements()
        if args.command in (None, 'menu'):
            if not sys.stdin.isatty():
                parser.print_help()
                return 0
            return menu()
        if args.command in ('workspace', 'favorite', 'recent', 'diagnostics', 'compare'):
            report = run_utility(args)
            deliver(report, args)
            return 1 if args.command == 'diagnostics' and any(item['status'] == 'failed' for item in report['data']['checks']) else 0
        if not 0 < args.timeout <= 60:
            parser.error('--timeout must be greater than 0 and at most 60')
        workspace_name = args.workspace
        if not args.target:
            if args.command not in WORKSPACE_TOOLS:
                raise ValueError('This tool needs an explicit target or value.')
            workspace = workspaces.get_workspace(workspace_name)
            workspace_name = workspace['name']
            args.target = workspace_default(args.command, workspace['target'])
            if args.target is None:
                raise ValueError('This tool needs an explicit IP address; the workspace target is a hostname.')
        elif workspace_name:
            workspaces.get_workspace(workspace_name)
        with Progress(DESCRIPTIONS[args.command], enabled=not args.json) as progress:
            report = execute(args.command, args.target, args.timeout, getattr(args, 'ports', None), getattr(args, 'pages', None),
                             getattr(args, 'max_links', None), getattr(args, 'include_external', False), progress if not args.json else None)
        workspaces.remember(args.target)
        if workspace_name:
            report['workspace'] = workspace_name
            path = workspaces.record_run(workspace_name, report)
            if not args.json:
                print(ui.message('Workspace run saved: ' + str(path), 'success'))
        deliver(report, args)
        return 0
    except (OSError, ValueError, KeyError, HTTPException) as error:
        if getattr(args, 'json', False):
            print(json.dumps({'error': str(error), 'tool': args.command}))
        else:
            with redirect_stdout(sys.stderr):
                error_report(error, getattr(args, 'target', None))
        return 1
    except (KeyboardInterrupt, EOFError):
        print('\nOpenTiger stopped.', file=sys.stderr)
        return 130


def deliver(report, args):
    if args.output:
        save(report, args.output)
    if args.html:
        export_html(report, args.html)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        render_report(report)
        if args.html:
            print(ui.message('HTML report saved: ' + args.html, 'success'))


def run_utility(args):
    if args.command == 'diagnostics':
        if not 0 < args.timeout <= 60:
            raise ValueError('Timeout must be greater than zero and at most 60.')
        return utility_report('diagnostics', diagnose(args.online, args.timeout))
    if args.command == 'compare':
        before = workspaces.read_json(Path(args.before))
        after = workspaces.read_json(Path(args.after))
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise ValueError('Choose two existing JSON report files.')
        result = compare_reports(before, after)
        result['started_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return result
    if args.command == 'recent':
        return utility_report('recent', {'recent_targets': workspaces.settings().get('recent_targets', [])})
    if args.command == 'favorite':
        favorites = (workspaces.settings().get('favorites', []) if args.action == 'list'
                     else workspaces.favorite(args.command_name or '', args.action))
        return utility_report('favorite', {'favorites': favorites})
    if args.action == 'create':
        if not args.name or not args.target:
            raise ValueError('Use: opentiger workspace create NAME TARGET')
        data = workspaces.create_workspace(args.name, args.target)
    elif args.action == 'use':
        if not args.name:
            raise ValueError('Use: opentiger workspace use NAME')
        data = workspaces.activate(args.name)
    elif args.action == 'list':
        data = {'active': workspaces.settings().get('active_workspace'), 'workspaces': workspaces.list_workspaces()}
    elif args.action == 'off':
        config = workspaces.settings()
        config['active_workspace'] = None
        workspaces.write_json(workspaces.home() / 'settings.json', config)
        data = {'active': None}
    elif args.action == 'history':
        workspace = workspaces.get_workspace(args.name)
        data = {'workspace': workspace, 'runs': [str(path) for path in workspaces.history(workspace['name'])]}
    else:
        data = workspaces.get_workspace(args.name)
    return utility_report('workspace', data)
