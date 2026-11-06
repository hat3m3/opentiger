"""User-local targets, preferences, and immutable investigation history."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import uuid


def home():
    return Path(os.environ.get('OPENTIGER_HOME', Path.home() / '.opentiger')).expanduser()


def read_json(path, default=None):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, UnicodeError) as error:
        raise ValueError(f'Invalid JSON in {path}; preserve a copy and repair it before retrying.') from error


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2, ensure_ascii=True)
        stream.write('\n')
    temporary.replace(path)


def settings():
    return read_json(home() / 'settings.json', {'active_workspace': None, 'recent_targets': [], 'favorites': []})


def workspace_path(name):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', name):
        raise ValueError('Workspace names need 1-64 letters, numbers, underscores, or hyphens.')
    return home() / 'workspaces' / name


def get_workspace(name=None):
    name = name or settings().get('active_workspace')
    if not name:
        raise ValueError('No active workspace. Use: opentiger workspace create NAME TARGET')
    path = workspace_path(name) / 'workspace.json'
    data = read_json(path)
    if data is None:
        raise ValueError(f'Workspace {name} does not exist.')
    return data


def create_workspace(name, target):
    from .extras import website_url
    website_url(target)  # Validate without contacting the target.
    folder = workspace_path(name)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / 'workspace.json'
    data = {'name': name, 'target': target, 'created_at': datetime.now(timezone.utc).isoformat()}
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
    activate(name)
    return data


def activate(name):
    data = get_workspace(name)
    config = settings()
    config['active_workspace'] = name
    write_json(home() / 'settings.json', config)
    return data


def list_workspaces():
    root = home() / 'workspaces'
    return [read_json(path) for path in sorted(root.glob('*/workspace.json'))] if root.exists() else []


def remember(target):
    config = settings()
    config['recent_targets'] = [target] + [item for item in config.get('recent_targets', []) if item != target][:11]
    write_json(home() / 'settings.json', config)


def favorite(command, action):
    from .catalog import MENU_TOOLS
    if command not in {item[1] for item in MENU_TOOLS}:
        raise ValueError('Choose a command listed in opentiger --help.')
    config = settings()
    favorites = config.get('favorites', [])
    if action == 'add' and command not in favorites:
        favorites.append(command)
    elif action == 'remove':
        favorites = [item for item in favorites if item != command]
    config['favorites'] = favorites
    write_json(home() / 'settings.json', config)
    return favorites


def record_run(name, report):
    get_workspace(name)
    folder = workspace_path(name) / 'runs'
    folder.mkdir(parents=True, exist_ok=True)
    identifier = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]
    path = folder / (identifier + '.json')
    with path.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, ensure_ascii=True)
    return path


def history(name):
    get_workspace(name)
    return sorted((workspace_path(name) / 'runs').glob('*.json'))
