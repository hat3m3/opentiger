import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from opentiger.extras import file_text, robots, url_decode, website_links, reverse_ip
from opentiger.terminal import ANSI, gradient


class ExtrasTest(unittest.TestCase):
    def test_link_extraction_resolves_deduplicates_and_filters(self):
        page = '<a href="/about#top">A</a><a href="/about">B</a><a href="https://other.test/a">C</a><a href="javascript:alert(1)">D</a>'
        with patch('opentiger.extras.read_page', return_value=(200, 'https://site.test/', page)):
            result = website_links('site.test')
        self.assertEqual(result['unique_links'], 2)
        self.assertEqual(result['internal'], ['https://site.test/about'])
        self.assertEqual(result['external'], ['https://other.test/a'])

    def test_robots_retains_partial_errors(self):
        with patch('opentiger.extras.read_page', side_effect=[(200, 'https://site.test/robots.txt', 'User-agent: *'), OSError('timeout')]):
            result = robots('site.test/path')
        self.assertEqual(result['files']['robots.txt']['status'], 200)
        self.assertEqual(result['files']['sitemap.xml']['error'], 'timeout')

    def test_file_strings_offsets_and_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'data.bin'
            file.write_bytes(b'\x00Hello world\x00' + b'long string\x00' * 110)
            result = file_text(str(file))
        self.assertEqual(result['strings'][0], {'offset': 1, 'text': 'Hello world', 'text_truncated': False})
        self.assertEqual(len(result['strings']), 100)

    def test_url_decode_preserves_repeated_and_blank_parameters(self):
        result = url_decode('https://site.test/a%20b?x=one&x=two&empty=#hi%20there')
        self.assertEqual(result['path'], '/a b')
        self.assertEqual(result['query_parameters'], {'x': ['one', 'two'], 'empty': ['']})
        self.assertEqual(result['fragment'], 'hi there')

    def test_reverse_lookup_only_accepts_ip(self):
        with self.assertRaises(ValueError):
            reverse_ip('example.com')

    def test_gradient_plain_and_ansi_have_same_text(self):
        text = 'OPENTIGER'
        self.assertEqual(gradient(text, False), text)
        self.assertEqual(ANSI.sub('', gradient(text, True)), text)
        self.assertIn('255;231;95', gradient(text, True))
        self.assertIn('255;116;24', gradient(text, True))
