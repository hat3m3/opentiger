import io
import json
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from opentiger import workbench
from opentiger.catalog import MENU_TOOLS
from opentiger.cli import TOOLS, BackToMenu, ask_value, execute, interactive_tool


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/away':
            self.send_response(302)
            self.send_header('Location', 'https://external.invalid/')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        if self.path == '/':
            self.wfile.write(b'<title>Test page</title><a href="/about">About</a><a href="/away">Away</a><a href="https://other.invalid/">Other</a><form action="/login" method="post"></form>')
        else:
            self.wfile.write(b'<title>About</title><a href="/">Home</a>')

    def log_message(self, *args):
        pass


class NativeTests(unittest.TestCase):
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

    def test_catalog_dispatch_is_complete_and_native(self):
        self.assertEqual(len(MENU_TOOLS), 31)
        self.assertEqual(set(TOOLS), {command for _, command in MENU_TOOLS})
        self.assertTrue(all(handler.__module__.startswith('opentiger.') for handler in TOOLS.values()))

    def test_page_review_and_connection_work_against_real_server(self):
        review = workbench.website_check(self.url)
        self.assertEqual(review['title'], 'Test page')
        self.assertFalse(review['uses_https'])
        self.assertEqual(review['forms'][0]['method'], 'POST')
        self.assertEqual(len(workbench.connection_check(self.url)['samples']), 3)
        self.assertTrue(all(row['status'] == 'connected' for row in workbench.connection_check(self.url)['samples']))

    def test_crawler_honors_limit_and_refuses_cross_origin_redirect(self):
        result = workbench.crawl(self.url, timeout=1, max_pages=3)
        self.assertEqual(result['pages_requested'], 3)
        self.assertTrue(any('Cross-origin' in row.get('error', '') for row in result['pages']))
        self.assertEqual(result['external_links_not_visited'], ['https://other.invalid/'])
        self.assertEqual(workbench.crawl(self.url, max_pages=1)['pages_requested'], 1)

    def test_page_saver_creates_exclusive_local_snapshot(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(workbench, 'REPORTS', Path(directory)):
            first = workbench.save_page(self.url)
            second = workbench.save_page(self.url)
            self.assertNotEqual(first['saved_file'], second['saved_file'])
            self.assertIn('<title>Test page</title>', Path(first['saved_file']).read_text())

    def test_clean_image_preserves_original_and_removes_text_and_exif(self):
        from PIL import Image, PngImagePlugin
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'original.png'
            info = PngImagePlugin.PngInfo()
            info.add_text('Author', 'Test author')
            image = Image.new('RGB', (5, 5), 'red')
            exif = image.getexif()
            exif[315] = 'Test author'
            image.save(path, pnginfo=info, exif=exif)
            original = path.read_bytes()
            metadata = workbench.file_metadata(str(path))
            self.assertEqual(metadata['image']['metadata']['Author'], 'Test author')
            result = workbench.clean_image(str(path))
            self.assertEqual(path.read_bytes(), original)
            with Image.open(result['clean_copy']) as clean:
                self.assertFalse(clean.getexif())
                self.assertNotIn('Author', clean.info)
                self.assertEqual(clean.convert('RGB').getpixel((0, 0)), (255, 0, 0))

    def test_lookup_links_are_encoded_and_never_claim_verified_accounts(self):
        search = workbench.search_links('site:example.com "hello world"')
        self.assertIn('%22hello+world%22', search['searches']['Google'])
        self.assertIn('not confirmed', workbench.username_links('example')['note'])
        self.assertIn('not checked', workbench.profile_link('example')['note'])
        self.assertIn('Ethereum', workbench.wallet_links('0x' + '1' * 40)['explorers'])
        with self.assertRaises(ValueError):
            workbench.profile_link('../bad')

    def test_host_discovery_refuses_large_networks_before_any_probe(self):
        with patch('socket.create_connection') as connect:
            with self.assertRaises(ValueError):
                workbench.host_discovery('192.168.0.0/16')
            connect.assert_not_called()

    def test_phone_lookup_uses_offline_numbering_metadata(self):
        result = workbench.phone_info('+442083661177')
        self.assertTrue(result['possible'])
        self.assertTrue(result['valid_format'])
        self.assertIn('not identify', result['note'])

    def test_overview_reports_partial_failure(self):
        with patch.object(workbench.tools, 'dns', return_value={'addresses': ['127.0.0.1']}), \
             patch.object(workbench.tools, 'http', side_effect=OSError('no HTTP')), \
             patch.object(workbench.tools, 'tls', side_effect=OSError('no TLS')):
            result = workbench.overview('localhost')
        self.assertEqual(result['checks']['addresses']['status'], 'ok')
        self.assertEqual(result['checks']['certificate']['status'], 'failed')

    def test_invalid_input_reprompts_without_falling_through(self):
        output = io.StringIO()
        with patch('opentiger.cli.ui.prompt', side_effect=['not-an-ip', 'back']), redirect_stdout(output):
            interactive_tool('ip-info')
        self.assertIn('REQUEST FAILED', output.getvalue())
        self.assertNotIn('Save JSON', output.getvalue())

    def test_back_and_required_value(self):
        with patch('opentiger.cli.ui.prompt', return_value='back'):
            with self.assertRaises(BackToMenu):
                ask_value('overview', 'Target')
        with self.assertRaises(ValueError):
            execute('overview', '')
