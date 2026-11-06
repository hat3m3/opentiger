"""Explicit local diagnostics, with optional public connectivity checks."""
import importlib.util
from http.client import HTTPException
import platform
import socket
import ssl
import sys
import uuid

from . import tools, workspaces


def diagnose(online=False, timeout=5):
    checks = []
    checks.append({'check': 'Python 3.11+', 'status': 'ok' if sys.version_info >= (3, 11) else 'failed', 'details': platform.python_version()})
    for module in ('dns', 'PIL', 'phonenumbers'):
        exists = importlib.util.find_spec(module) is not None
        checks.append({'check': module, 'status': 'ok' if exists else 'failed', 'details': 'Installed' if exists else 'Press I to install requirements.'})
    try:
        addresses = {row[4][0] for row in socket.getaddrinfo('localhost', None)}
        checks.append({'check': 'Local DNS resolver', 'status': 'ok', 'details': ', '.join(sorted(addresses))})
    except OSError as error:
        checks.append({'check': 'Local DNS resolver', 'status': 'failed', 'details': str(error)})
    try:
        context = ssl.create_default_context()
        checks.append({'check': 'Certificate trust store', 'status': 'ok' if context.verify_mode == ssl.CERT_REQUIRED else 'failed',
                       'details': f'{len(context.get_ca_certs())} CA certificates loaded; verification enabled. This does not prove a particular server will validate.'})
    except (OSError, ssl.SSLError) as error:
        checks.append({'check': 'Certificate trust store', 'status': 'failed', 'details': str(error)})
    try:
        folder = workspaces.home() / 'reports'
        folder.mkdir(parents=True, exist_ok=True)
        probe = folder / ('.write-check-' + uuid.uuid4().hex)
        with probe.open('x', encoding='utf-8') as stream:
            stream.write('OpenTiger diagnostics')
        probe.unlink()
        checks.append({'check': 'Writable report storage', 'status': 'ok', 'details': str(folder)})
    except OSError as error:
        checks.append({'check': 'Writable report storage', 'status': 'failed', 'details': str(error)})
    if online:
        try:
            with tools.fetch('https://example.com', timeout) as response:
                checks.append({'check': 'Public HTTPS connectivity', 'status': 'ok' if response.status < 400 else 'failed', 'details': f'example.com returned HTTP {response.status} with TLS verification.'})
        except (OSError, ValueError, HTTPException) as error:
            checks.append({'check': 'Public HTTPS connectivity', 'status': 'failed', 'details': str(error)})
    return {'checks': checks, 'online_checks': online, 'python_executable': sys.executable,
            'note': 'Local checks do not require administrator privileges. Public HTTPS is contacted only with --online.'}
