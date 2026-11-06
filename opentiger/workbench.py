"""OpenTiger's native network, web, lookup, and file workflows."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
import ipaddress
from pathlib import Path
import re
import socket
import time
import urllib.parse
import urllib.request
from http.client import HTTPException
import uuid

from . import extras, tools

REPORTS = Path(__file__).resolve().parents[1] / 'reports'


def overview(target, timeout=8, progress=None):
    from .investigations import website_overview
    return website_overview(target, timeout, progress)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = []
        self.in_title = False
        self.forms = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'title':
            self.in_title = True
        if tag == 'form':
            self.forms.append({'action': attrs.get('action', ''), 'method': attrs.get('method', 'get').upper()})

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data)


def website_check(target, timeout=8):
    url = extras.website_url(target)
    status, final, text = extras.read_page(url, timeout)
    if status >= 400:
        raise ValueError(f'Website returned HTTP {status}.')
    parser = PageParser()
    parser.feed(text)
    forms = []
    for form in parser.forms:
        action = urllib.parse.urljoin(final, form['action'])
        forms.append({'action': action, 'method': form['method'],
                      'uses_https': urllib.parse.urlsplit(action).scheme == 'https'})
    return {'source': final, 'http_status': status, 'title': ''.join(parser.title).strip(),
            'uses_https': urllib.parse.urlsplit(final).scheme == 'https', 'forms': forms,
            'note': 'Passive page review only. Forms are never submitted; these observations are not a vulnerability verdict.'}


def crawl(target, timeout=8, max_pages=10):
    if not 1 <= max_pages <= 30:
        raise ValueError('Choose between 1 and 30 pages.')
    start = extras.website_url(target)
    # Establish the canonical origin once. Subsequent requests stay on that origin.
    status, canonical, text = extras.read_page(start, timeout)
    if status >= 400:
        raise ValueError(f'Website returned HTTP {status}.')
    origin = urllib.parse.urlsplit(canonical)
    origin = (origin.scheme.lower(), origin.netloc.lower())
    queue, visited, pages, external = deque([canonical]), set(), [], set()

    class SameOriginRedirect(tools.HttpRedirects):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            parsed = urllib.parse.urlsplit(newurl)
            if (parsed.scheme.lower(), parsed.netloc.lower()) != origin:
                raise ValueError('Cross-origin redirect skipped.')
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(SameOriginRedirect())
    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        try:
            if url == canonical:
                current_status, page = status, text
            else:
                request = urllib.request.Request(url, headers={'User-Agent': 'OpenTiger/0.1.0'})
                with opener.open(request, timeout=timeout) as response:
                    current_status = response.status
                    if 'html' not in response.headers.get('Content-Type', '').lower():
                        pages.append({'url': url, 'status': current_status, 'result': 'Non-HTML skipped'})
                        continue
                    raw = response.read(2_000_001)
                    if len(raw) > 2_000_000:
                        raise ValueError('Page exceeds 2 MB.')
                    page = raw.decode(response.headers.get_content_charset() or 'utf-8', errors='replace')
            parser = extras.LinkParser()
            parser.feed(page)
            pages.append({'url': url, 'status': current_status, 'links': len(parser.links)})
            for href in parser.links:
                link = urllib.parse.urldefrag(urllib.parse.urljoin(url, href))[0]
                parsed = urllib.parse.urlsplit(link)
                if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password:
                    continue
                if (parsed.scheme.lower(), parsed.netloc.lower()) != origin:
                    if len(external) < 200:
                        external.add(link)
                elif link not in visited and link not in queue and len(queue) < 200:
                    queue.append(link)
        except (OSError, ValueError) as error:
            pages.append({'url': url, 'error': str(error)})
    return {'start': canonical, 'pages_requested': len(visited), 'page_limit': max_pages,
            'pages': pages, 'external_links_not_visited': sorted(external), 'more_pages_queued': bool(queue),
            'note': 'Bounded HTML crawl; no JavaScript, forms, login, or robots-rule enforcement. Initial canonical redirect may change origin.'}


def connection_check(target, timeout=8):
    name = tools.host(target)
    parsed = urllib.parse.urlsplit(target if '://' in target else '//' + target)
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    samples = []
    for attempt in range(1, 4):
        started = time.perf_counter()
        try:
            with socket.create_connection((name, port), timeout=timeout):
                pass
            samples.append({'attempt': attempt, 'status': 'connected',
                            'milliseconds': round((time.perf_counter() - started) * 1000, 2)})
        except OSError as error:
            samples.append({'attempt': attempt, 'status': 'failed', 'error': str(error)})
    return {'hostname': name, 'port': port, 'samples': samples,
            'note': 'Three TCP connection attempts; this is not an ICMP ping or an availability history.'}


def host_discovery(target, timeout=8):
    network = ipaddress.ip_network(target.strip(), strict=False)
    if network.num_addresses > 64:
        raise ValueError('Use a subnet containing at most 64 addresses (IPv4 /26 or smaller).')

    def inspect(address):
        open_ports = []
        for port in (22, 80, 443):
            try:
                with socket.create_connection((str(address), port), timeout=min(timeout, 1)):
                    open_ports.append(port)
            except OSError:
                pass
        return {'ip': str(address), 'open_ports': ', '.join(map(str, open_ports)) or 'None observed'}

    with ThreadPoolExecutor(max_workers=8) as executor:
        rows = list(executor.map(inspect, network.hosts()))
    return {'subnet': str(network), 'hosts_checked': len(rows), 'hosts': rows,
            'note': 'TCP checks on ports 22, 80, 443 only. No open port does not mean a host is offline.'}


def search_links(target, timeout=8):
    query = target.strip()
    if not query:
        raise ValueError('Enter a search query, optionally including site:, intitle:, or quoted text.')
    encoded = urllib.parse.quote_plus(query)
    return {'query': query, 'searches': {'Google': 'https://www.google.com/search?q=' + encoded,
                                        'Bing': 'https://www.bing.com/search?q=' + encoded,
                                        'DuckDuckGo': 'https://duckduckgo.com/?q=' + encoded},
            'note': 'Search links are generated locally. No search is submitted and no browser is opened.'}


def wallet_links(target, timeout=8):
    address = target.strip()
    if re.fullmatch(r'0x[0-9a-fA-F]{40}', address):
        links = {'Ethereum': 'https://etherscan.io/address/' + address,
                 'Base': 'https://basescan.org/address/' + address}
        kind = 'EVM-format address'
    elif re.fullmatch(r'(?:bc1[ac-hj-np-z02-9]{11,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})', address):
        links = {'Bitcoin': 'https://mempool.space/address/' + address}
        kind = 'Bitcoin-format address'
    else:
        raise ValueError('Enter a Bitcoin or 0x-prefixed EVM address.')
    return {'address': address, 'format_hint': kind, 'explorers': links,
            'note': 'Format check and explorer links only; no checksum, balance, transaction, ownership, or chain validation.'}


def username_links(target, timeout=8):
    name = target.strip().lstrip('@')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,39}', name):
        raise ValueError('Enter a username using letters, numbers, dots, underscores, or hyphens (up to 39 characters).')
    encoded = urllib.parse.quote(name, safe='')
    return {'username': name, 'profiles_to_check': {'GitHub': 'https://github.com/' + encoded,
                                                  'Reddit': 'https://www.reddit.com/user/' + encoded,
                                                  'YouTube': 'https://www.youtube.com/@' + encoded},
            'note': 'Candidate links, not confirmed accounts. The same username does not establish the same person.'}


def email_search(target, timeout=8):
    address = target.strip()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', address):
        raise ValueError('Enter an email address such as name@example.com.')
    return search_links('"' + address.replace('"', '') + '"', timeout)


def email_info(target, timeout=8):
    address = target.strip()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', address):
        raise ValueError('Enter an email address such as name@example.com.')
    result = extras.email_domain(address, timeout)
    result['email'] = address
    return result


def ip_info(target, timeout=8):
    address = ipaddress.ip_address(target.strip())
    result = {'ip': str(address), 'version': address.version, 'private': address.is_private,
              'global': address.is_global, 'loopback': address.is_loopback, 'multicast': address.is_multicast}
    try:
        result['reverse_dns'] = socket.gethostbyaddr(str(address))[0]
    except OSError:
        result['reverse_dns'] = 'No PTR returned'
    if address.is_global:
        try:
            result['registration'] = tools.registration(str(address), timeout)
        except (OSError, ValueError) as error:
            result['registration'] = {'error': str(error)}
    return result


def phone_info(target, timeout=8):
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone as phone_timezone
    except ImportError as error:
        raise ValueError('Phone Lookup needs phonenumbers. Press I to install requirements.') from error
    if not target.strip().startswith('+'):
        raise ValueError('Include the country code, for example +442083661177.')
    try:
        number = phonenumbers.parse(target, None)
    except phonenumbers.NumberParseException as error:
        raise ValueError(str(error)) from error
    return {'international': phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'possible': phonenumbers.is_possible_number(number), 'valid_format': phonenumbers.is_valid_number(number),
            'region': geocoder.description_for_number(number, 'en'), 'original_carrier_hint': carrier.name_for_number(number, 'en'),
            'timezones': list(phone_timezone.time_zones_for_number(number)),
            'note': 'Offline numbering-plan data. Does not identify an owner, live location, current carrier, or whether the number is active.'}


def profile_link(target, timeout=8):
    name = target.strip().lstrip('@')
    if not re.fullmatch(r'[A-Za-z0-9_.]{1,30}', name):
        raise ValueError('Enter a profile username using letters, numbers, dots, or underscores (up to 30 characters).')
    return {'username': name, 'profile': 'https://www.instagram.com/' + name + '/',
            'note': 'Public profile link only. Existence, identity, followers, and private data are not checked.'}


def image_library():
    try:
        from PIL import Image, ExifTags, ImageOps
    except ImportError as error:
        raise ValueError('Image tools need Pillow. Press I to install requirements.') from error
    return Image, ExifTags, ImageOps


def file_metadata(target, timeout=8):
    path = Path(target).expanduser().resolve(strict=True)
    result = tools.file_info(str(path), timeout)
    stat = path.stat()
    result['modified_utc'] = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
    Image, ExifTags, _ = image_library()
    try:
        with Image.open(path) as image:
            result['image'] = {'format': image.format, 'width': image.width, 'height': image.height, 'mode': image.mode,
                               'frames': getattr(image, 'n_frames', 1),
                               'metadata': {str(key): str(value)[:1000] for key, value in image.info.items()},
                               'exif': {ExifTags.TAGS.get(key, str(key)): str(value)[:1000]
                                        for key, value in image.getexif().items()}}
    except Image.UnidentifiedImageError:
        result['image'] = {'status': 'Not a supported image; basic file information shown.'}
    return result


def clean_image(target, timeout=8):
    path = Path(target).expanduser().resolve(strict=True)
    Image, _, ImageOps = image_library()
    with Image.open(path) as image:
        if image.format not in ('PNG', 'JPEG') or getattr(image, 'n_frames', 1) != 1:
            raise ValueError('Use a single-frame PNG or JPEG. Other formats are not modified.')
        format_name = image.format
        pixels = ImageOps.exif_transpose(image).convert('RGBA' if format_name == 'PNG' else 'RGB')
        # Allocate a new image from pixels so metadata is not inherited by copy().
        cleaned = Image.frombytes(pixels.mode, pixels.size, pixels.tobytes())
        destination = path.with_name(path.stem + '.clean-' + uuid.uuid4().hex[:8] + path.suffix)
        with destination.open('xb') as stream:
            cleaned.save(stream, format=format_name, **({'quality': 95} if format_name == 'JPEG' else {}))
    return {'original': str(path), 'clean_copy': str(destination), 'original_preserved': True,
            'note': 'Writes a new pixel-only PNG/JPEG without EXIF or text metadata. JPEG is recompressed; visible content is not anonymized.'}


def save_page(target, timeout=8):
    status, final, text = extras.read_page(extras.website_url(target), timeout)
    if status >= 400:
        raise ValueError(f'Website returned HTTP {status}.')
    folder = REPORTS / 'pages'
    folder.mkdir(parents=True, exist_ok=True)
    destination = folder / ('page-' + uuid.uuid4().hex[:12] + '.html')
    with destination.open('x', encoding='utf-8') as stream:
        stream.write(text)
    return {'source': final, 'saved_file': str(destination), 'characters': len(text),
            'note': 'Saves one HTML response. Resources are not downloaded, scripts are not executed, and the file is not opened automatically.'}


HANDLERS = {'overview': overview, 'website-check': website_check, 'port-scan': tools.ports,
            'crawl': crawl, 'connection': connection_check, 'hosts': host_discovery,
            'search': search_links, 'wallet': wallet_links, 'username': username_links,
            'email-search': email_search, 'email-info': email_info, 'ip-info': ip_info,
            'phone': phone_info, 'profile': profile_link, 'metadata': file_metadata,
            'clean-image': clean_image, 'save-page': save_page}
