import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from scenarios import benchmark


class DissertationScenarios(unittest.TestCase):
    def test_three_scenarios_and_exported_measurements(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            summary = benchmark(2, directory)
            self.assertTrue(summary['benchmark']['all_runs_passed'], summary['checks'])
            self.assertTrue(all(summary['checks'].values()))
            self.assertEqual([b['snapshots'] for b in summary['blocks']], [0, 1, 1, 2, 2])
            self.assertEqual(len(summary['access_checks']), 4)
            for name in ('phishing', 'identity_theft', 'data_breach'):
                report = json.loads((Path(directory) / name / 'evidence.json').read_text())
                self.assertTrue(report['integrity']['history_chain_valid'])
                self.assertTrue(report['integrity']['block_chain_valid'])
                self.assertTrue(Path(report['evidence']['offchain_meta']['url_or_path']).is_file())
            identity = json.loads((Path(directory) / 'identity_theft/evidence.json').read_text())
            self.assertEqual(len(identity['evidence']['history']), 8)
            phishing = json.loads((Path(directory) / 'phishing/evidence.json').read_text())
            request = next(iter(phishing['linked_lab_requests'].values()))
            self.assertEqual([f['status'] for f in request['findings']], ['RESOLVED', 'RESOLVED'])
            derived = [json.loads(f['lab_response']) for f in request['findings']]
            self.assertEqual(derived[0]['observations'][0]['kind'], 'email_headers')
            self.assertEqual(derived[1]['observations'][0]['failures'], 1)
            self.assertTrue((Path(directory) / 'timings.csv').is_file())
            self.assertTrue((Path(directory) / 'RESULTS.md').is_file())
            for metric in summary['benchmark']['metrics'].values():
                self.assertGreater(metric['samples'], 0)
                self.assertLessEqual(metric['median_seconds'], metric['max_seconds'])
