import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from opentiger.cli import execute, safe, save, menu_table
from opentiger.catalog import MENU_TOOLS, MENU_GROUPS
from opentiger.tools import file_info, host, http, parse_ports, ports


class QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Set-Cookie', 'secret=value')
        self.end_headers()

    def log_message(self, *args):
        pass


class ToolsTest(unittest.TestCase):
    def test_category_numbers_are_consecutive_and_dispatch_in_display_order(self):
        expected = 1
        for _, numbers in MENU_GROUPS:
            self.assertEqual(list(numbers), list(range(expected, expected + len(numbers))))
            expected += len(numbers)
        self.assertEqual(expected, len(MENU_TOOLS) + 1)
        self.assertEqual([command for _, command in MENU_TOOLS[:8]],
                         ['overview', 'port-scan', 'connection', 'hosts', 'dns', 'ports', 'dns-records', 'reverse-ip'])

    def test_complete_menu_at_multiple_widths(self):
        for width in (40, 80, 160):
            output = menu_table(width)
            for index in range(1, len(MENU_TOOLS) + 1):
                self.assertEqual(output.count(f'[{index:02}]'), 1)
            self.assertTrue(all(len(line) <= max(width, 34) for line in output.splitlines()))

    def test_port_validation(self):
        self.assertEqual(parse_ports('80,443,80,8000-8002'), [80, 443, 8000, 8001, 8002])
        for invalid in ('0', '65536', '2-1', '1-257', '1-2-3'):
            with self.assertRaises(ValueError):
                parse_ports(invalid)

    def test_host_and_terminal_safety(self):
        self.assertEqual(host('https://example.com/path'), 'example.com')
        self.assertEqual(host('[::1]'), '::1')
        with self.assertRaises(ValueError):
            host('https://user:secret@example.com')
        self.assertNotIn('\x1b', safe('\x1b[31mremote'))

    def test_hash_and_report_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.txt'
            path.write_bytes(b'OpenTiger')
            self.assertEqual(file_info(str(path))['sha256'], hashlib.sha256(b'OpenTiger').hexdigest())
            report = execute('file', str(path))
            output = Path(directory) / 'report.json'
            save(report, output)
            self.assertEqual(json.loads(output.read_text())['tool'], 'file')
            with self.assertRaises(FileExistsError):
                save(report, output)

    def test_local_http_and_tcp(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_port
            result = http(f'http://127.0.0.1:{port}')
            self.assertEqual(result['status'], 200)
            self.assertNotIn('set-cookie', result['headers'])
            self.assertTrue(result['header_review']['x-content-type-options']['present'])
            self.assertEqual(ports('127.0.0.1', port_spec=str(port))['results'][0]['state'], 'open')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
