import io
import json
import socket
import unittest
import tempfile
import os
from contextlib import redirect_stdout
from unittest.mock import patch

from opentiger.cli import main
from opentiger.results import render_report, error_report


class ResultTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        context = patch.dict(os.environ, {'OPENTIGER_HOME': directory.name})
        context.start()
        self.addCleanup(context.stop)

    def test_ports_report_preserves_all_states_and_wraps(self):
        report = {'tool': 'ports', 'target': 'localhost', 'duration_seconds': 0.02,
                  'data': {'results': [{'port': 80, 'state': 'open', 'conventional_service': 'http'},
                                       {'port': 81, 'state': 'unreachable_or_filtered', 'conventional_service': 'unknown'}]}}
        output = io.StringIO()
        with redirect_stdout(output):
            render_report(report, color=False, columns=60)
        text = output.getvalue()
        self.assertIn('1 open / 2 ports checked', text)
        self.assertIn('80', text)
        self.assertIn('81', text)
        self.assertNotIn('\x1b', text)
        self.assertTrue(all(len(line) <= 60 for line in text.splitlines()))

    def test_dns_failure_gets_recovery_hint(self):
        output = io.StringIO()
        with redirect_stdout(output):
            error_report(socket.gaierror('no such host'), 'example.invalid', color=False)
        self.assertIn('Hostname could not be resolved', output.getvalue())
        self.assertIn('Check the spelling', output.getvalue())

    def test_remote_escape_cannot_format_report(self):
        output = io.StringIO()
        with redirect_stdout(output):
            render_report({'tool': 'dns', 'target': 'test', 'data': {'hostname': '\x1b[31mremote\x1b[0m'}}, color=False)
        self.assertIn('remote', output.getvalue())
        self.assertNotIn('\x1b', output.getvalue())

    def test_json_mode_stays_machine_readable(self):
        output = io.StringIO()
        with patch('opentiger.cli.TOOLS', {'dns': lambda *args, **kwargs: {'hostname': 'test'}}), redirect_stdout(output):
            code = main(['dns', 'test', '--json'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())['data']['hostname'], 'test')
