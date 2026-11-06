"""Structured investigations and bounded, evidence-based web checks."""
from http.client import HTTPException
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from . import tools, extras

ERRORS = (OSError, ValueError, HTTPException)


def website_overview(target, timeout=8, progress=None):
    from .workbench import website_check
    url = extras.website_url(target)
    checks = {}
    interrupted = False
    started = time.perf_counter()
    plan = [('addresses', lambda: tools.dns(target, timeout)),
            ('website', lambda: tools.http(url, timeout)),
            ('certificate', None),
            ('page', lambda: website_check(url, timeout)),
            ('links', lambda: extras.website_links(url, timeout)),
            ('discovery_files', lambda: extras.robots(url, timeout))]
    for index, (name, function) in enumerate(plan):
        try:
            if progress:
                progress(index, len(plan), name.replace('_', ' '))
            if name == 'certificate':
                final_url = checks.get('website', {}).get('data', {}).get('final_url', url)
                if not final_url.startswith('https://'):
                    checks[name] = {'status': 'skipped', 'reason': 'HTTP target; no TLS connection was attempted.'}
                    continue
                function = lambda: tools.tls(final_url, timeout)
            if name in ('page', 'links', 'discovery_files') and checks.get('website', {}).get('status') != 'ok':
                checks[name] = {'status': 'skipped', 'reason': 'Website request failed.'}
                continue
            began = time.perf_counter()
            checks[name] = {'status': 'ok', 'data': function(), 'duration_seconds': round(time.perf_counter() - began, 4)}
        except KeyboardInterrupt:
            interrupted = True
            checks[name] = {'status': 'cancelled', 'reason': 'Interrupted by user.'}
            break
        except ERRORS as error:
            checks[name] = {'status': 'failed', 'error': str(error)}
    if progress:
        progress(len(checks), len(plan), 'cancelled — partial results retained' if interrupted else 'collection finished')
    observations, issues, errors = [], [], []
    for name, check in checks.items():
        if check['status'] == 'failed':
            errors.append({'check': name, 'error': check['error']})
    addresses = checks.get('addresses', {}).get('data', {}).get('addresses', [])
    if addresses:
        observations.append({'finding': 'Resolved addresses', 'evidence': ', '.join(addresses)})
    website = checks.get('website', {}).get('data', {})
    if website:
        observations.append({'finding': 'HTTP response', 'evidence': f"{website['status']} at {website['final_url']}"})
        if website['status'] >= 400:
            issues.append({'finding': 'HTTP error response', 'evidence': str(website['status']), 'next_step': 'Check the route and access requirements.'})
        if not website['final_url'].startswith('https://'):
            issues.append({'finding': 'Unencrypted HTTP', 'evidence': website['final_url'], 'next_step': 'Check whether the site should redirect to HTTPS.'})
        for header, review in website.get('header_review', {}).items():
            if header == 'strict-transport-security' and not website['final_url'].startswith('https://'):
                continue
            if not review['present']:
                issues.append({'finding': 'Header not observed', 'evidence': header,
                               'next_step': review['meaning'] + ' Review suitability for this site.'})
    certificate = checks.get('certificate', {}).get('data', {})
    if certificate:
        observations.append({'finding': 'Verified certificate', 'evidence': str(certificate.get('valid_until'))})
        if certificate.get('days_remaining', 999) <= 30:
            issues.append({'finding': 'Certificate renewal window', 'evidence': f"{certificate['days_remaining']} days remaining", 'next_step': 'Confirm certificate renewal is scheduled.'})
    links = checks.get('links', {}).get('data', {})
    if links:
        observations.append({'finding': 'Links on the starting page', 'evidence': str(links.get('unique_links', 0))})
    page = checks.get('page', {}).get('data', {})
    for form in page.get('forms', []):
        if not form['uses_https']:
            issues.append({'finding': 'Form action uses HTTP', 'evidence': form['action'], 'next_step': 'Review whether the form should submit over HTTPS.'})
    return {'status': 'cancelled' if interrupted else 'partial' if errors else 'complete',
            'summary': {'checks_completed': sum(item['status'] == 'ok' for item in checks.values()),
                        'observations': len(observations), 'potential_issues': len(issues), 'lookup_errors': len(errors)},
            'observations': observations, 'potential_issues': issues, 'lookup_errors': errors, 'checks': checks,
            'elapsed_seconds': round(time.perf_counter() - started, 4),
            'note': 'Potential issues are review prompts, not confirmed vulnerabilities. Errors are collection failures. This overview does not submit forms, crawl the full site, or scan ports.'}


def username_check(target, timeout=8, progress=None):
    name = target.strip().lstrip('@')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,39}', name):
        raise ValueError('Use a username of up to 39 letters, digits, dots, underscores, or hyphens.')
    encoded = urllib.parse.quote(name, safe='')
    providers = [('GitHub', f'https://api.github.com/users/{encoded}', f'https://github.com/{encoded}'),
                 ('GitLab', f'https://gitlab.com/api/v4/users?username={encoded}', f'https://gitlab.com/{encoded}')]
    results = []
    interrupted = False
    for index, (site, endpoint, public_url) in enumerate(providers):
        row = {'site': site, 'status': 'unknown', 'url': public_url, 'evidence': ''}
        try:
            if progress:
                progress(index, len(providers), site)
            with tools.fetch(endpoint, timeout) as response:
                code = response.status
                row['http_status'] = code
                if code in (401, 403, 429):
                    row.update(status='blocked_or_rate_limited', evidence=f'API returned HTTP {code}; existence was not inferred.')
                elif code == 404:
                    row.update(status='not_found', evidence='API returned 404; private or restricted accounts may also be hidden.')
                elif code == 200:
                    raw = response.read(256_001)
                    if len(raw) > 256_000:
                        raise ValueError('API response exceeds 256 KB.')
                    payload = json.loads(raw)
                    if site == 'GitHub' and isinstance(payload, dict):
                        exact = str(payload.get('login', '')).casefold() == name.casefold()
                        row.update(status='found' if exact else 'unknown', evidence='API returned the exact login.' if exact else 'Unexpected API response; no exact login.')
                    elif site == 'GitLab' and isinstance(payload, list):
                        exact = any(isinstance(user, dict) and str(user.get('username', '')).casefold() == name.casefold() for user in payload)
                        row.update(status='found' if exact else 'not_found', evidence='Exact username returned by API.' if exact else 'API returned no exact username.')
                    else:
                        row['evidence'] = 'Unexpected API response format.'
                else:
                    row['evidence'] = f'API returned HTTP {code}; existence was not inferred.'
        except KeyboardInterrupt:
            interrupted = True
            break
        except ERRORS as error:
            row['evidence'] = str(error)
        results.append(row)
    if progress:
        progress(len(results), len(providers), 'profile checks finished')
    return {'username': name, 'status': 'cancelled' if interrupted else 'complete', 'results': results,
            'note': 'At most two public API requests. Found means the API returned that username, not that both accounts belong to the same person. Missing, blocked, and unknown responses are kept distinct.'}


def broken_links(target, timeout=8, max_links=20, include_external=False, progress=None):
    if not 1 <= max_links <= 50:
        raise ValueError('Choose 1-50 links per run.')
    collected = extras.website_links(target, timeout)
    origin = urllib.parse.urlsplit(collected['source'])
    origin = (origin.scheme, origin.netloc)
    candidates = sorted(set(collected['internal'] + collected['external']))
    if not include_external:
        candidates = [url for url in candidates if (urllib.parse.urlsplit(url).scheme, urllib.parse.urlsplit(url).netloc) == origin]
    selected = candidates[:max_links]

    class ScopedRedirect(tools.HttpRedirects):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            parsed = urllib.parse.urlsplit(newurl)
            if not include_external and (parsed.scheme, parsed.netloc) != origin:
                raise ValueError('Redirect leaves the selected origin; skipped.')
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(ScopedRedirect())
    results, interrupted = [], False
    for index, url in enumerate(selected):
        row = {'url': url, 'status': 'unknown'}
        try:
            if progress:
                progress(index, len(selected), url)
            for method in ('HEAD', 'GET'):
                request = urllib.request.Request(url, method=method, headers={'User-Agent': 'OpenTiger/0.1.0', 'Range': 'bytes=0-0'})
                try:
                    response = opener.open(request, timeout=timeout)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    code = response.status
                if code not in (405, 501) or method == 'GET':
                    break
            state = ('broken' if code in (404, 410) else 'restricted' if code in (401, 403)
                     else 'rate_limited' if code == 429 else 'server_error' if code >= 500
                     else 'reachable' if code < 400 else 'request_error')
            row.update(status=state, http_status=code)
        except KeyboardInterrupt:
            interrupted = True
            break
        except ERRORS as error:
            row['error'] = str(error)
        results.append(row)
    if progress:
        progress(len(results), len(selected), 'link checks finished')
    return {'source': collected['source'], 'status': 'cancelled' if interrupted else 'complete',
            'summary': {'links_checked': len(results), 'broken': sum(row['status'] == 'broken' for row in results),
                        'unknown': sum(row['status'] == 'unknown' for row in results)},
            'max_links': max_links, 'external_enabled': include_external, 'results': results,
            'more_links_available': len(candidates) > len(selected) or collected['truncated'],
            'note': 'One starting page, then bounded HEAD checks with a GET fallback for 405/501. Only 404/410 are labeled broken. Response bodies from checked links are not read; redirects are limited to the selected scope.'}
