from contextlib import redirect_stdout
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from opentiger import workspaces
from opentiger.cli import main, menu
from opentiger.diagnostics import diagnose
from opentiger.investigations import website_overview, username_check, broken_links
from opentiger.reporting import compare_reports, export_html
from opentiger.tools import certificate_expiry


class Handler(BaseHTTPRequestHandler):
    counts = []

    def do_HEAD(self):
        type(self).counts.append(('HEAD', self.path))
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'https://external.invalid/target')
        else:
            self.send_response({'/missing': 404, '/restricted': 403, '/fallback': 405}.get(self.path, 200))
        self.end_headers()

    def do_GET(self):
        type(self).counts.append(('GET', self.path))
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'<title>Fixture</title><a href="/missing">Missing</a><a href="/fallback">Fallback</a><a href="/restricted">Restricted</a><a href="/redirect">Redirect</a><a href="https://external.invalid/">External</a><form action="/login"></form>')

    def log_message(self, *args):
        pass


class Reply:
    def __init__(self, status, body):
        self.status, self.body = status, body

    def read(self, size=-1):
        return self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class EnhancementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        context = patch.dict(os.environ, {'OPENTIGER_HOME': self.directory.name})
        context.start()
        self.addCleanup(context.stop)
        Handler.counts = []

    def call(self, *args):
        stream = io.StringIO()
        with redirect_stdout(stream):
            status = main(list(args))
        return status, stream.getvalue()

    def test_workspace_is_persistent_and_cannot_escape_root(self):
        workspaces.create_workspace('demo', self.url)
        self.assertEqual(workspaces.get_workspace()['target'], self.url)
        self.assertEqual(len(workspaces.list_workspaces()), 1)
        with self.assertRaises(FileExistsError):
            workspaces.create_workspace('demo', 'example.com')
        self.assertEqual(workspaces.get_workspace()['target'], self.url)
        with self.assertRaises(ValueError):
            workspaces.create_workspace('../escape', 'example.com')

    def test_overview_can_use_workspace_and_persist_run_with_html(self):
        self.assertEqual(self.call('workspace', 'create', 'demo', self.url, '--json')[0], 0)
        html = Path(self.directory.name) / 'report.html'
        code, output = self.call('overview', '--workspace', 'demo', '--timeout', '1', '--json', '--html', str(html))
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertEqual(report['target'], self.url)
        self.assertEqual(report['workspace'], 'demo')
        self.assertTrue(html.exists())
        history = workspaces.history('demo')
        self.assertEqual(len(history), 1)
        self.assertEqual(json.loads(history[0].read_text())['data']['status'], 'complete')
        self.assertEqual(workspaces.settings()['recent_targets'][0], self.url)

    def test_history_and_exports_do_not_overwrite(self):
        workspaces.create_workspace('demo', self.url)
        report = {'tool': 'dns', 'target': 'localhost', 'data': {}}
        first = workspaces.record_run('demo', report)
        second = workspaces.record_run('demo', report)
        self.assertNotEqual(first, second)
        output = Path(self.directory.name) / 'report.html'
        export_html(report, output)
        before = output.read_bytes()
        with self.assertRaises(FileExistsError):
            export_html(report, output)
        self.assertEqual(output.read_bytes(), before)

    def test_overview_separates_errors_from_findings_and_skips_plain_http_tls(self):
        report = website_overview(self.url, timeout=1)
        self.assertEqual(report['checks']['certificate']['status'], 'skipped')
        self.assertFalse(report['lookup_errors'])
        self.assertTrue(any(row['finding'] == 'Unencrypted HTTP' for row in report['potential_issues']))
        self.assertTrue(report['observations'])
        self.assertEqual(report['summary']['checks_completed'], 5)

    def test_interruption_retains_prior_overview_checks(self):
        def cancel_at_http(done, total, name):
            if name == 'website':
                raise KeyboardInterrupt()
        result = website_overview(self.url, timeout=1, progress=cancel_at_http)
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(result['checks']['addresses']['status'], 'ok')
        self.assertEqual(result['checks']['website']['status'], 'cancelled')

    def test_broken_links_keep_restricted_distinct_and_use_head_fallback(self):
        result = broken_links(self.url, timeout=1, max_links=4)
        statuses = {row['url'].rsplit('/', 1)[-1]: row['status'] for row in result['results']}
        self.assertEqual(statuses['missing'], 'broken')
        self.assertEqual(statuses['restricted'], 'restricted')
        self.assertEqual(statuses['fallback'], 'reachable')
        self.assertEqual(statuses['redirect'], 'unknown')
        self.assertIn(('HEAD', '/fallback'), Handler.counts)
        self.assertIn(('GET', '/fallback'), Handler.counts)
        self.assertFalse(result['external_enabled'])
        self.assertEqual(len(broken_links(self.url, max_links=1)['results']), 1)

    def test_profile_checks_never_turn_blocked_or_bad_payload_into_found(self):
        with patch('opentiger.investigations.tools.fetch', side_effect=[Reply(200, b'{"login":"example"}'), Reply(403, b'blocked')]):
            rows = username_check('example')['results']
        self.assertEqual(rows[0]['status'], 'found')
        self.assertEqual(rows[1]['status'], 'blocked_or_rate_limited')
        with patch('opentiger.investigations.tools.fetch', side_effect=[Reply(200, b'<html>challenge</html>'), Reply(200, b'[]')]):
            rows = username_check('example')['results']
        self.assertEqual(rows[0]['status'], 'unknown')
        self.assertEqual(rows[1]['status'], 'not_found')

    def test_profile_cancellation_keeps_the_completed_provider(self):
        def cancel(done, total, name):
            if name == 'GitLab':
                raise KeyboardInterrupt()
        with patch('opentiger.investigations.tools.fetch', return_value=Reply(200, b'{"login":"example"}')):
            result = username_check('example', progress=cancel)
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(len(result['results']), 1)
        self.assertEqual(result['results'][0]['status'], 'found')

    def test_external_link_checks_require_explicit_opt_in(self):
        second = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=second.serve_forever, daemon=True)
        thread.start()
        outside = f'http://127.0.0.1:{second.server_port}/good'
        collected = {'source': self.url, 'internal': [self.url + '/missing'], 'external': [outside], 'truncated': False}
        try:
            with patch('opentiger.investigations.extras.website_links', return_value=collected):
                local = broken_links(self.url)
                expanded = broken_links(self.url, include_external=True)
            self.assertEqual(len(local['results']), 1)
            self.assertEqual(len(expanded['results']), 2)
            self.assertEqual(next(row for row in expanded['results'] if row['url'] == outside)['status'], 'reachable')
        finally:
            second.shutdown()
            second.server_close()
            thread.join()

    def test_html_escapes_remote_markup_and_rejects_active_links(self):
        path = Path(self.directory.name) / 'escaped.html'
        report = {'tool': 'dns', 'target': '<script>alert(1)</script>',
                  'data': {'payload': '<img src=x onerror=alert(1)>', 'bad_link': 'javascript:alert(1)', 'malformed': 'http://[bad'}}
        export_html(report, path)
        html = path.read_text()
        self.assertNotIn('<script>', html)
        self.assertNotIn('<img src=x', html)
        self.assertNotIn('href="javascript:', html)
        self.assertIn('&lt;img', html)
        self.assertIn('Content-Security-Policy', html)

    def test_comparison_ignores_noise_but_detects_real_address_change(self):
        first = {'tool': 'dns-records', 'target': 'example.com', 'data': {'records': {'A': {'ttl': 300, 'values': ['1.1.1.1', '2.2.2.2']}}}}
        reordered = {'tool': 'dns-records', 'target': 'example.com', 'data': {'records': {'A': {'ttl': 12, 'values': ['2.2.2.2', '1.1.1.1']}}}}
        self.assertEqual(compare_reports(first, reordered)['data']['change_count'], 0)
        reordered['data']['records']['A']['values'] = ['3.3.3.3']
        self.assertEqual(compare_reports(first, reordered)['data']['change_count'], 1)
        with self.assertRaises(ValueError):
            compare_reports(first, {'tool': 'http', 'data': {}})

    def test_favorites_recent_and_menu_search(self):
        workspaces.favorite('dns', 'add')
        workspaces.favorite('dns', 'add')
        self.assertEqual(workspaces.settings()['favorites'], ['dns'])
        workspaces.remember('one.test')
        workspaces.remember('two.test')
        workspaces.remember('one.test')
        self.assertEqual(workspaces.settings()['recent_targets'], ['one.test', 'two.test'])
        with patch('opentiger.cli.ui.prompt', side_effect=['dns', 'q']), patch('opentiger.cli.interactive_tool') as run, redirect_stdout(io.StringIO()):
            self.assertEqual(menu(), 0)
        run.assert_called_once_with('dns')

    def test_diagnostics_do_not_contact_public_hosts_without_online_flag(self):
        with patch('opentiger.diagnostics.tools.fetch') as fetch:
            result = diagnose()
        fetch.assert_not_called()
        self.assertFalse(result['online_checks'])
        self.assertTrue(any(row['check'] == 'Writable report storage' and row['status'] == 'ok' for row in result['checks']))
        self.assertFalse(list((workspaces.home() / 'reports').glob('.write-check-*')))

    def test_certificate_expiry_has_renewal_countdown(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        result = certificate_expiry({'notAfter': 'Jan 20 00:00:00 2026 GMT'}, now)
        self.assertEqual(result['days_remaining'], 19)
        self.assertEqual(result['expiry_status'], 'renew_soon')
