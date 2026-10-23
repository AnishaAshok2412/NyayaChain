import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

import nyayachain_dissertation as n
from evidence_analysis import analyze_evidence


class EnteredEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.bc = n.MetadataBlockchain()
        self.police, self.lab, self.court = (n.SEED_USERS[k] for k in ('P001', 'L001', 'C001'))

    def register(self, text, filename='events.csv'):
        path = self.folder / filename
        path.write_text(text)
        meta = n.ingest_offchain_evidence(str(path))
        eid = self.bc.add_evidence_record(self.police, 'Tester', 'T001', 'USER-CASE',
            'Tester-entered case', 'Test evidence', 'log', 'Phishing / Online Fraud', meta)
        return eid, path

    def test_different_inputs_generate_different_results_and_final_report(self):
        for count in (1, 4):
            eid, path = self.register('user,source_ip,result\n' + 'new_user,203.0.113.42,FAILED\n' * count,
                                      f'events{count}.csv')
            self.bc.transfer_custody(self.police, eid, self.lab)
            request = self.bc.issue_lab_request(self.police, 'USER-CASE', 'Count authentication failures',
                [{'evidence_id': eid, 'description': 'Count failed authentication events'}])
            with self.assertRaises(ValueError):
                self.bc.respond_to_finding(self.lab, request.request_id, request.findings[0].finding_id,
                    'premature', n.FindingStatus.RESOLVED)
            self.bc.acknowledge_lab_request(self.lab, request.request_id)
            result = self.bc.preview_evidence_analysis(self.lab, eid, 'authentication')
            self.assertEqual(result['observations'][0]['failures'], count)
            self.assertEqual(result['observations'][0]['source_ips'], ['203.0.113.42'])
            self.bc.map_legal_sections(self.police, eid, ['Sec. 318(4)'], [], [], [])
            with self.assertRaises(ValueError):
                self.bc.commit_evidence_to_blockchain(self.police, eid)
            self.bc.respond_to_finding(self.lab, request.request_id, request.findings[0].finding_id,
                json.dumps(result), n.FindingStatus.RESOLVED, 'Parsed authentication log', result['engine'])
            self.bc.commit_evidence_to_blockchain(self.police, eid)
            self.assertFalse(self.bc.procedure_status(eid)['final_snapshot_mined'])
            self.bc.mine_block(self.police)
            report = json.loads(n.ReportGenerator(self.bc).json_report(self.court, eid))
            self.assertTrue(report['procedure_status']['final_snapshot_mined'])
            self.assertTrue(report['integrity']['history_chain_valid'])
            history_result = next(a['payload']['findings'] for a in report['evidence']['history'] if a['action_type'] == 'LOG_ANALYSIS')
            self.assertEqual(json.loads(history_result)['observations'][0]['failures'], count)
            self.assertIn('USER-CASE', n.ReportGenerator(self.bc).text_report(self.court, eid))

    def test_modified_evidence_is_rejected_without_logging(self):
        eid, path = self.register('user,result\na,SUCCESS\n')
        before = len(self.bc.world_state[eid].history)
        path.write_text('user,result\na,FAILED\n')
        with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
            self.bc.preview_evidence_analysis(self.lab, eid, 'authentication')
        self.assertEqual(before, len(self.bc.world_state[eid].history))
        with self.assertRaises(PermissionError):
            self.bc.preview_evidence_analysis(self.court, eid, 'authentication')

    def test_zip_email_identity_network_and_unsupported_formats(self):
        path = self.folder / 'mixed.zip'
        with ZipFile(path, 'w') as archive:
            archive.writestr('mail.eml', 'Date: Thu, 02 Jan 2025 12:00:00 +0000\nFrom: alice@example.invalid\nX-Originating-IP: 203.0.113.8\n\n')
            archive.writestr('identity.json', json.dumps([{'device': 'USER-DEVICE', 'imsi': 'USER-IMSI', 'peer': 'PEER-A'}]*3))
            archive.writestr('network.csv', 'destination,bytes\n203.0.113.9,100\n203.0.113.9,250\n')
            archive.writestr('web.csv', 'path\n/search?q=UNION%20SELECT\n/home\n')
            archive.writestr('capture.pcap', b'unsupported packets')
        source = n.ingest_offchain_evidence(str(path))
        meta = {'url_or_path': str(path), 'sha256': source['evidence_hash'], 'filename': path.name}
        email = analyze_evidence(meta, 'email')
        self.assertEqual(email['observations'][0]['values']['From'], ['alice@example.invalid'])
        identity = analyze_evidence(meta, 'identity')
        self.assertEqual(identity['observations'][0]['communication_pairs'][0]['events'], 3)
        network = analyze_evidence(meta, 'network')
        flow = next(o for o in network['observations'] if o['kind'] == 'network_metadata')
        self.assertEqual(flow['sum_valid_byte_counts'], 350)
        web = next(o for o in network['observations'] if o['kind'] == 'web_request_review')
        self.assertEqual(len(web['sql_like_markers']), 1)
        self.assertTrue(any(s['source'] == 'capture.pcap' for s in network['skipped']))

    def test_unsupported_and_unmatched_data_require_manual_examination(self):
        eid, path = self.register('This is not a supported event schema', 'unknown.txt')
        result = self.bc.preview_evidence_analysis(self.lab, eid, 'authentication')
        self.assertEqual(result['status'], 'MANUAL_EXAMINATION_REQUIRED')
        self.assertEqual(result['observations'], [])

    def test_terminal_finding_uses_entered_data(self):
        eid, _ = self.register('username,status\nTester,SUCCESS\nTester,SUCCESS\n')
        request = self.bc.issue_lab_request(self.police, 'USER-CASE', 'Review events',
            [{'evidence_id': eid, 'description': 'Review exported login outcomes'}])
        self.bc.acknowledge_lab_request(self.lab, request.request_id)
        answers = iter([request.request_id, request.findings[0].finding_id, '1', 'authentication', '', '1'])
        with patch.object(n, 'ask', side_effect=lambda _: next(answers)), redirect_stdout(io.StringIO()):
            n._lab_respond_to_finding(self.lab, self.bc)
        result = json.loads(request.findings[0].lab_response)
        self.assertEqual(result['observations'][0]['successes'], 2)
        self.assertEqual(request.findings[0].status, n.FindingStatus.RESOLVED)
