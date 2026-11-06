"""Independent, read-only inspection tools. No terminal rendering here."""
import concurrent.futures
import errno
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import mimetypes
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def host(value):
    value = value.strip()
    parsed = urllib.parse.urlsplit(value if '://' in value else '//' + value)
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Enter a hostname, IP address, or URL without credentials.')
    return parsed.hostname.encode('idna').decode('ascii')


class HttpRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme not in ('http', 'https'):
            raise ValueError('Only HTTP and HTTPS redirects are supported.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, timeout=8):
    if urllib.parse.urlsplit(url).scheme not in ('http', 'https'):
        raise ValueError('Only HTTP and HTTPS URLs are supported.')
    opener = urllib.request.build_opener(HttpRedirects())
    request = urllib.request.Request(url, headers={'User-Agent': 'OpenTiger/0.1.0'})
    try:
        return opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as response:
        return response


def dns(target, timeout=8):
    name = host(target)
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)})
    return {'hostname': name, 'addresses': addresses,
            'explanation': 'A/AAAA addresses from your operating system resolver; cached or split DNS may differ.'}


def registration(target, timeout=8):
    name = host(target)
    try:
        ipaddress.ip_address(name)
        kind = 'ip'
    except ValueError:
        kind = 'domain'
    url = f'https://rdap.org/{kind}/{urllib.parse.quote(name, safe="")}'
    with fetch(url, timeout) as response:
        if response.status != 200:
            raise ValueError(f'RDAP returned HTTP {response.status}; registration may be unavailable.')
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError('RDAP response exceeded 2 MB.')
        data = json.loads(raw)
    return {'query': name, 'source': response.url, 'name': data.get('ldhName', data.get('name')),
            'handle': data.get('handle'), 'status': data.get('status', []),
            'events': data.get('events', []), 'nameservers': [n.get('ldhName') for n in data.get('nameservers', [])],
            'network_start': data.get('startAddress'), 'network_end': data.get('endAddress'),
            'explanation': 'Public registration data, not proof of who operates a website. Personal data may be redacted.'}


def http(target, timeout=8):
    url = target if '://' in target else 'https://' + target
    host(url)
    with fetch(url, timeout) as response:
        headers = {k.lower(): v for k, v in response.headers.items()
                   if k.lower() not in ('set-cookie', 'authorization', 'proxy-authorization')}
        expected = {'content-security-policy': 'Restricts permitted content sources.',
                    'strict-transport-security': 'Tells browsers to use HTTPS.',
                    'x-content-type-options': 'Prevents MIME type guessing.',
                    'referrer-policy': 'Controls referrer information sent to other sites.'}
        return {'requested_url': url, 'final_url': response.url, 'status': response.status,
                'headers': headers, 'header_review': {k: {'present': k in headers, 'meaning': v} for k, v in expected.items()},
                'explanation': 'One HTTP GET with redirects. Missing headers are review prompts, not confirmed vulnerabilities.'}


def tls(target, timeout=8):
    name = host(target)
    parsed = urllib.parse.urlsplit(target if '://' in target else '//' + target)
    port = parsed.port or 443
    with socket.create_connection((name, port), timeout=timeout) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname=name) as secure:
            cert = secure.getpeercert()
            return {'hostname': name, 'port': port, 'protocol': secure.version(), 'cipher': secure.cipher(),
                    'issuer': cert.get('issuer'), 'subject': cert.get('subject'),
                    'valid_from': cert.get('notBefore'), 'valid_until': cert.get('notAfter'),
                    'subject_alternative_names': cert.get('subjectAltName'), 'certificate_verified': True,
                    **certificate_expiry(cert),
                    'explanation': 'Certificate chain and hostname verified using system trust. This is not a full TLS audit.'}


def certificate_expiry(certificate, now=None):
    if not certificate.get('notAfter'):
        return {'expiry_status': 'not_provided'}
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate['notAfter']), timezone.utc)
    remaining = (expires - (now or datetime.now(timezone.utc))).total_seconds()
    days = int(remaining // 86400)
    return {'expires_at_utc': expires.isoformat(), 'days_remaining': days,
            'expiry_status': 'expired' if remaining <= 0 else 'renew_soon' if days <= 30 else 'valid'}


def parse_ports(value):
    ports = set()
    for part in value.split(','):
        bounds = part.strip().split('-')
        if len(bounds) > 2:
            raise ValueError('Use comma-separated ports or ranges, such as 80,443,8000-8010.')
        start, end = int(bounds[0]), int(bounds[-1])
        if not 1 <= start <= end <= 65535 or end - start >= 256:
            raise ValueError('Ports must be 1–65535, with at most 256 ports per run.')
        ports.update(range(start, end + 1))
        if len(ports) > 256:
            raise ValueError('At most 256 ports per run.')
    return sorted(ports)


def ports(target, timeout=2, port_spec='22,53,80,443,445,3389,8000,8080,8443'):
    name = host(target)
    selected = parse_ports(port_spec)
    # Resolve once so every probe refers to the same destination.
    family, _, _, _, address = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)[0]

    def probe(port):
        endpoint = (address[0], port, *address[2:])
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            result = connection.connect_ex(endpoint)
        state = 'open' if result == 0 else 'closed' if result in (errno.ECONNREFUSED, 10061) else 'unreachable_or_filtered'
        try:
            service = socket.getservbyport(port, 'tcp')
        except OSError:
            service = 'unknown'
        return {'port': port, 'state': state, 'conventional_service': service}

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(probe, selected))
    return {'hostname': name, 'resolved_ip': address[0], 'transport': 'tcp', 'results': results,
            'explanation': 'TCP connection checks on one resolved address. Service names are conventions, not identified software.'}


def file_info(target, timeout=8):
    path = Path(target).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError('Choose a regular file.')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        prefix = stream.read(32)
        digest.update(prefix)
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest.hexdigest(),
            'extension_mime_guess': mimetypes.guess_type(path.name)[0], 'first_32_bytes_hex': prefix.hex(),
            'explanation': 'Local inspection only. A hash identifies bytes; it does not establish whether a file is safe.'}


TOOLS = {'dns': dns, 'rdap': registration, 'http': http, 'tls': tls, 'ports': ports, 'file': file_info}
