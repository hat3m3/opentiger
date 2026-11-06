"""Small reconnaissance and file tools with bounded inputs and source attribution."""
import ipaddress
import re
import socket
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path

from .tools import fetch, host


def dns_records(target, timeout=8):
    try:
        import dns.exception
        import dns.resolver
    except ImportError as error:
        raise ValueError('DNS Records needs dnspython. Use the project .venv or install requirements.txt.') from error
    name = host(target)
    resolver = dns.resolver.Resolver()
    results = {}
    for kind in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA'):
        try:
            answer = resolver.resolve(name, kind, lifetime=timeout)
            results[kind] = {'status': 'ok', 'values': [str(item) for item in answer], 'ttl': answer.rrset.ttl}
        except dns.resolver.NXDOMAIN:
            results[kind] = {'status': 'domain_not_found', 'values': []}
        except dns.resolver.NoAnswer:
            results[kind] = {'status': 'no_record', 'values': []}
        except dns.exception.DNSException as error:
            results[kind] = {'status': 'lookup_failed', 'error': str(error), 'values': []}
    return {'domain': name, 'records': results}


def reverse_ip(target, timeout=8):
    address = str(ipaddress.ip_address(target.strip()))
    name, aliases, addresses = socket.gethostbyaddr(address)
    return {'ip': address, 'hostname': name, 'aliases': aliases, 'addresses': addresses,
            'note': 'PTR records can be absent or controlled by the network owner. This does not list every website on an IP.'}


def email_domain(target, timeout=8):
    domain = target.rsplit('@', 1)[-1].strip()
    result = dns_records(domain, timeout)
    records = result['records']
    mx = records['MX']
    txt = records['TXT']
    spf = [value for value in txt['values'] if value.strip('"').lower().startswith('v=spf1')]
    try:
        import dns.exception
        import dns.resolver
        answer = dns.resolver.resolve('_dmarc.' + result['domain'], 'TXT', lifetime=timeout)
        dmarc = {'status': 'ok', 'values': [str(item) for item in answer]}
    except dns.resolver.NoAnswer:
        dmarc = {'status': 'no_record', 'values': []}
    except dns.resolver.NXDOMAIN:
        dmarc = {'status': 'no_record', 'values': []}
    except dns.exception.DNSException as error:
        dmarc = {'status': 'lookup_failed', 'error': str(error), 'values': []}
    return {'domain': result['domain'], 'mail_servers': mx,
            'null_mx': mx['status'] == 'ok' and mx['values'] == ['0 .'],
            'spf': {'dns_status': txt['status'], 'records': spf}, 'dmarc': dmarc,
            'note': 'Domain configuration only. A null MX (0 .) explicitly rejects inbound mail. This does not verify that a mailbox exists or evaluate complete mail policy.'}


def website_url(target):
    url = target if '://' in target else 'https://' + target
    host(url)
    if urllib.parse.urlsplit(url).scheme not in ('http', 'https'):
        raise ValueError('Enter an HTTP or HTTPS URL.')
    return url


def read_page(url, timeout):
    with fetch(url, timeout) as response:
        data = response.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError('Response exceeds the 2 MB limit.')
        return response.status, response.url, data.decode(response.headers.get_content_charset() or 'utf-8', errors='replace')


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            href = dict(attrs).get('href')
            if href:
                self.links.append(href)


def website_links(target, timeout=8):
    status, final_url, page = read_page(website_url(target), timeout)
    if status >= 400:
        raise ValueError(f'Website returned HTTP {status}.')
    parser = LinkParser()
    parser.feed(page)
    links = sorted({urllib.parse.urldefrag(urllib.parse.urljoin(final_url, link))[0]
                    for link in parser.links if urllib.parse.urlsplit(urllib.parse.urljoin(final_url, link)).scheme in ('http', 'https')})
    name = urllib.parse.urlsplit(final_url).hostname
    internal = [link for link in links if urllib.parse.urlsplit(link).hostname == name]
    external = [link for link in links if urllib.parse.urlsplit(link).hostname != name]
    return {'source': final_url, 'status': status, 'unique_links': len(links),
            'internal': internal[:200], 'external': external[:200],
            'truncated': len(internal) > 200 or len(external) > 200,
            'note': 'Links from one HTML page; JavaScript is not executed and linked pages are not requested.'}


def robots(target, timeout=8):
    url = urllib.parse.urlsplit(website_url(target))
    base = urllib.parse.urlunsplit((url.scheme, url.netloc, '/', '', ''))
    results = {}
    for path in ('robots.txt', 'sitemap.xml'):
        source = urllib.parse.urljoin(base, path)
        try:
            status, final_url, text = read_page(source, timeout)
            results[path] = {'source': final_url, 'status': status, 'preview': text[:12000],
                             'preview_truncated': len(text) > 12000}
        except (OSError, ValueError) as error:
            results[path] = {'source': source, 'error': str(error)}
    return {'files': results, 'note': 'Public discovery files. Listed paths are not proof of sensitive content; no listed paths are visited.'}


def file_text(target, timeout=8):
    path = Path(target).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError('Choose a regular file.')
    with path.open('rb') as stream:
        raw = stream.read(16_000_001)
    sampled = raw[:16_000_000]
    matches = re.finditer(rb'[\x20-\x7e]{6,}', sampled)
    found = []
    for match in matches:
        if len(found) == 100:
            break
        found.append({'offset': match.start(), 'text': match.group()[:300].decode('ascii'),
                      'text_truncated': len(match.group()) > 300})
    return {'file': str(path), 'bytes_read': len(sampled), 'file_truncated': len(raw) > len(sampled),
            'strings': found, 'note': 'First 100 printable ASCII strings of at least six characters, from up to 16 MB. The file is never executed.'}


def url_decode(target, timeout=8):
    parsed = urllib.parse.urlsplit(target)
    return {'input': target, 'decoded': urllib.parse.unquote(target), 'scheme': parsed.scheme,
            'hostname': parsed.hostname, 'path': urllib.parse.unquote(parsed.path),
            'query_parameters': urllib.parse.parse_qs(parsed.query, keep_blank_values=True),
            'fragment': urllib.parse.unquote(parsed.fragment),
            'note': 'Local decoding only. The URL is not opened.'}


EXTRA_HANDLERS = {'dns-records': dns_records, 'reverse-ip': reverse_ip, 'email-domain': email_domain,
                  'website-links': website_links, 'robots': robots, 'file-text': file_text, 'url-decode': url_decode}
