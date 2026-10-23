"""Reproduce dissertation workflows with synthetic evidence and measured timings.

No forensic tools, live attacks, real customer records or legal certification.
"""
import argparse
import copy
import csv
import hashlib
import io
import json
import platform
import statistics
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from time import perf_counter
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import nyayachain_dissertation as n

ROOT = Path(__file__).resolve().parent
LIMITS = {
    'Evidence registration': 0.1,
    'Custody transfer logging': 0.1,
    'Lab request issuance': 0.1,
    'Analysis action logging': 0.1,
    'History report generation (8+ actions)': 0.5,
    'Demonstration certificate generation': 0.2,
    'JSON report generation': 0.3,
}

FIXTURES = {
    'phishing': {
        'email_headers.txt': 'X-Synthetic: true\nDate: Wed, 01 Jan 2025 10:00:00 +0000\nFrom: demo@example.invalid\nX-Originating-IP: 192.0.2.10\n',
        'server_access.csv': 'timestamp,user,source_ip,result\n2025-01-01T10:01:00Z,demo,192.0.2.10,FAILED\n2025-01-01T10:02:00Z,demo,192.0.2.10,SUCCESS\n',
    },
    'identity_theft': {
        'imsi_metadata.csv': 'device,imsi\nSIM-DEMO-001,SYNTHETIC-IMSI-001\n',
        'call_logs.csv': 'timestamp,device,peer\n2025-01-02T10:00:00Z,SIM-DEMO-001,DEMO-PEER-001\n2025-01-02T10:05:00Z,SIM-DEMO-001,DEMO-PEER-001\n',
    },
    'data_breach': {
        'network_metadata.csv': 'timestamp,source,destination,bytes,label\n2025-01-03T10:00:00Z,192.0.2.20,198.51.100.30,4096,illustrative_external_destination\n',
        'web_access.csv': 'timestamp,path,status\n2025-01-03T09:59:00Z,/search?q=demo_sql_injection_marker,200\n',
        'case_context.txt': 'SYNTHETIC CASE: alleged exposure of 50000 records. No customer records or PCAP are included. Destination and SQL marker are illustrative, not validated attack attribution.\n',
    },
}


def write_fixtures(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, files in FIXTURES.items():
        path = destination / f'{name}.zip'
        # Fixed ZIP member times keep fixture bytes reproducible between runs.
        with ZipFile(path, 'w') as archive:
            for filename, content in sorted(files.items()):
                info = ZipInfo(filename, date_time=(2025, 1, 1, 0, 0, 0))
                info.compress_type = ZIP_DEFLATED
                archive.writestr(info, content.encode('utf-8'))
        paths[name] = path
    return paths


def run_scenarios(fixture_dir):
    if not n._AES_AVAILABLE:
        raise RuntimeError('Install requirements.txt; scenario validation requires AES encryption.')
    samples = []

    def measure(operation, function, *args, **kwargs):
        start = perf_counter()
        value = function(*args, **kwargs)
        samples.append({'operation': operation, 'seconds': perf_counter() - start})
        return value

    bc = n.MetadataBlockchain()
    reporter = n.ReportGenerator(bc)
    p1, p2, l1, l2, court = (n.SEED_USERS[k] for k in ('P001', 'P002', 'L001', 'L002', 'C001'))
    fixture_paths = write_fixtures(fixture_dir)
    ids = {}

    def register(name, actor, case_id, evidence_type, category):
        meta = measure('ZIP file hashing (separate from registration)',
                       n.ingest_offchain_evidence, str(fixture_paths[name]))
        eid = measure('Evidence registration', bc.add_evidence_record,
                      actor, actor.name, actor.badge_id, case_id,
                      f'Synthetic {name} case', f'SYNTHETIC {name} evidence',
                      evidence_type, category, meta, 'Synthetic crime scene', 'Synthetic laboratory')
        ids[name] = eid
        return eid

    def transfer(actor, eid, holder):
        return measure('Custody transfer logging', bc.transfer_custody,
                       actor, eid, holder, 'Synthetic scenario custody transfer')

    def analysis(actor, eid, description, findings, tool):
        return measure('Analysis action logging', bc.log_analysis,
                       actor, eid, description, findings, tool)

    def seal(actor, eid, bns, bsa):
        measure('Legal mapping', bc.map_legal_sections, actor, eid, bns, [], bsa, [])
        measure('Final snapshot submission', bc.commit_evidence_to_blockchain, actor, eid)

    def mine():
        return measure('Proof-of-work mining (separate)', bc.mine_block, p1)

    # Scenario 1: registration is mined separately, then the completed snapshot.
    s1 = register('phishing', p1, 'CASE-2025-CF001', 'log', 'Phishing / Online Fraud')
    mine()
    transfer(p1, s1, l1)
    request = measure('Lab request issuance', bc.issue_lab_request,
                      p1, 'CASE-2025-CF001', 'Synthetic phishing investigation', [
                          {'evidence_id': s1, 'description': 'Extract email timestamp and sender IP', 'priority': 'HIGH'},
                          {'evidence_id': s1, 'description': 'Review server access events', 'priority': 'HIGH'},
                      ])
    bc.acknowledge_lab_request(l1, request.request_id)
    for finding, profile in zip(request.findings, ('email', 'authentication')):
        result = measure('Evidence parsing (separate)', bc.preview_evidence_analysis, l1, s1, profile)
        if result['status'] != 'OBSERVATIONS_AVAILABLE':
            raise RuntimeError('Synthetic scenario fixture did not produce observations')
        measure('Finding response logging', bc.respond_to_finding, l1, request.request_id,
                finding.finding_id, json.dumps(result), n.FindingStatus.RESOLVED,
                'Data-derived ' + profile, result['engine'])
    seal(p2, s1, ['Sec. 318(4)', 'Sec. 336(1)'], ['Sec. 63', 'Sec. 61'])
    mine()

    # Scenario 2: exactly eight evidence-history entries, without a VIEW event.
    s2 = register('identity_theft', p2, 'CASE-2025-ID001', 'comm_record',
                  'Cheating by Personation (Sec. 319)')
    transfer(p2, s2, p1)
    transfer(p1, s2, l1)
    identity_result = measure('Evidence parsing (separate)', bc.preview_evidence_analysis, l1, s2, 'identity')
    analysis(l1, s2, 'IMSI metadata examination', json.dumps(identity_result), identity_result['engine'])
    transfer(l1, s2, l2)
    call_result = measure('Evidence parsing (separate)', bc.preview_evidence_analysis, l2, s2, 'identity')
    analysis(l2, s2, 'Call log correlation', json.dumps(call_result), call_result['engine'])
    seal(p1, s2, ['Sec. 319(1)', 'Sec. 318(4)'], ['Sec. 63', 'Sec. 61'])
    mine()

    # Scenario 3: metadata fixture, not a PCAP parser or attack detector.
    s3 = register('data_breach', p1, 'CASE-2025-DB001', 'network_trace',
                  'Data Breach / Unauthorised Access')
    network_result = measure('Evidence parsing (separate)', bc.preview_evidence_analysis, l2, s3, 'network')
    analysis(l2, s3, 'Network traffic metadata review', json.dumps(network_result), network_result['engine'])
    analysis(l2, s3, 'Web server access review', json.dumps(network_result), network_result['engine'])
    seal(p1, s3, ['Sec. 111(1)'], ['Sec. 63', 'Sec. 61'])
    mine()

    # The report names old 65A/65B labels as BSA provisions. Do not copy those
    # labels into the new demonstration; legal mappings remain unverified tags.
    rejection_specs = [
        ('Court cannot register evidence', lambda: bc.add_evidence_record(court, '', '', '', '', '', '', '', {})),
        ('Lab cannot register evidence', lambda: bc.add_evidence_record(l1, '', '', '', '', '', '', '', {})),
        ('Lab cannot submit final snapshot', lambda: bc.commit_evidence_to_blockchain(l1, s1)),
        ('Court cannot log analysis', lambda: bc.log_analysis(court, s1, 'test', 'test')),
    ]
    access_checks = []
    for label, action in rejection_specs:
        before = json.dumps({'evidence': [r.to_dict() for r in bc.world_state.values()],
                             'requests': [r.to_dict() for r in bc.lab_requests.values()],
                             'chain': bc.chain, 'pending': bc.pending}, sort_keys=True)
        try:
            action()
            denied = False
        except PermissionError:
            denied = True
        after = json.dumps({'evidence': [r.to_dict() for r in bc.world_state.values()],
                            'requests': [r.to_dict() for r in bc.lab_requests.values()],
                            'chain': bc.chain, 'pending': bc.pending}, sort_keys=True)
        access_checks.append({'check': label, 'passed': denied and before == after})

    expected_s2 = ['REGISTER', 'TRANSFER_CUSTODY', 'TRANSFER_CUSTODY', 'LOG_ANALYSIS',
                   'TRANSFER_CUSTODY', 'LOG_ANALYSIS', 'LEGAL_MAPPING', 'BLOCKCHAIN_COMMIT']
    reports = {}
    for name, eid in ids.items():
        reports[name] = {
            'chain_of_custody.txt': measure('History report generation (8+ actions)' if len(bc.world_state[eid].history) >= 8 else 'History report generation (<8 actions)',
                                           reporter.text_report, court, eid),
            'certificate_demo.txt': measure('Demonstration certificate generation', reporter.bsa_certificate, court, eid),
            'evidence.json': measure('JSON report generation', reporter.json_report, court, eid),
        }
    reports['phishing']['lab_findings.txt'] = reporter.lab_request_report(court, request.request_id)

    histories_valid = {name: reporter._verify_history_chain(bc.world_state[eid]) for name, eid in ids.items()}
    history_copy = copy.deepcopy(bc.world_state[s2])
    history_copy.history[0].payload['case_id'] = 'TAMPERED'
    history_tamper_detected = not reporter._verify_history_chain(history_copy)
    chain_copy = copy.deepcopy(bc)
    chain_copy.chain[1]['records'][0]['evidence_id'] = 'TAMPERED'
    block_tamper_detected = not chain_copy.verify_chain()
    final_snapshots_valid = {}
    for name, eid in ids.items():
        snapshots = [r for block in bc.chain for r in block['records']
                     if r.get('evidence_id') == eid and r.get('final_commit')]
        final_snapshots_valid[name] = len(snapshots) == 1 and n.aes_decrypt_json(snapshots[0]['encrypted']) == bc.world_state[eid].to_dict()
    hash_checks = {}
    for name, eid in ids.items():
        raw = fixture_paths[name].read_bytes()
        meta = bc.world_state[eid].offchain_meta
        hash_checks[name] = meta['sha256'] == hashlib.sha256(raw).hexdigest() and meta['size_bytes'] == len(raw)

    checks = {
        'three_cases_registered': len(bc.world_state) == 3,
        'five_blocks': len(bc.chain) == 5,
        'six_snapshots_mined': sum(len(b['records']) for b in bc.chain) == 6,
        'no_pending_snapshots': not bc.pending,
        'two_phishing_findings_resolved': len(request.findings) == 2 and all(f.status == n.FindingStatus.RESOLVED for f in request.findings),
        'phishing_request_completed': request.status == n.RequestStatus.COMPLETED,
        'identity_eight_action_sequence': [a.action_type.value for a in bc.world_state[s2].history] == expected_s2,
        'data_breach_two_analysis_entries': sum(a.action_type == n.ActionType.LOG_ANALYSIS for a in bc.world_state[s3].history) == 2,
        'all_histories_valid': all(histories_valid.values()),
        'block_chain_valid': bc.verify_chain(),
        'four_access_rejections_without_mutation': all(c['passed'] for c in access_checks),
        'history_tamper_detected': history_tamper_detected,
        'block_tamper_detected': block_tamper_detected,
        'encrypted_final_snapshots_match': all(final_snapshots_valid.values()),
        'evidence_file_hashes_match': all(hash_checks.values()),
    }
    summary = {'checks': checks, 'all_passed': all(checks.values()), 'access_checks': access_checks,
               'history_integrity': histories_valid,
               'scenarios': {name: {'case_id': bc.world_state[eid].case_id, 'evidence_id': eid,
                                    'history_actions': [a.action_type.value for a in bc.world_state[eid].history]}
                             for name, eid in ids.items()},
               'blocks': [{'index': b['index'], 'snapshots': len(b['records']), 'hash': bc.hash(b)} for b in bc.chain],
               'notes': ['Observations derived from synthetic export bytes; external forensic tools are not executed.',
                         'Legal tags and certificate templates are not validated legal certification.',
                         'BSA 65A/65B labels in the dissertation are not reproduced.',
                         'Five blocks reflect the documented mining schedule, not scalability evidence.']}
    return summary, samples, reports


def benchmark(runs, output):
    if runs < 1:
        raise ValueError('runs must be at least 1')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    rows, run_checks = [], []
    for run in range(1, runs + 1):
        buffer = io.StringIO()
        with tempfile.TemporaryDirectory(prefix='nyayachain-validation-') as temporary:
            with redirect_stdout(buffer):
                summary, samples, reports = run_scenarios(output / 'synthetic_evidence' if run == runs else temporary)
            run_checks.append(summary['all_passed'])
            rows.extend({'run': run, **sample} for sample in samples)
            if run == runs:
                for name, contents in reports.items():
                    folder = output / name
                    folder.mkdir(exist_ok=True)
                    for filename, content in contents.items():
                        (folder / filename).write_text(content, encoding='utf-8')
                (output / 'execution.log').write_text(buffer.getvalue(), encoding='utf-8')
    groups = {}
    for row in rows:
        groups.setdefault(row['operation'], []).append(row['seconds'])
    metrics = {}
    for name, values in groups.items():
        values.sort()
        p95 = values[max(0, (95 * len(values) + 99) // 100 - 1)]
        target = LIMITS.get(name)
        metrics[name] = {'samples': len(values), 'median_seconds': statistics.median(values),
                         'p95_seconds': p95, 'max_seconds': max(values),
                         'dissertation_target_seconds': target,
                         'all_samples_under_target': max(values) < target if target is not None else None}
    summary['benchmark'] = {'runs': runs, 'all_runs_passed': all(run_checks),
                            'environment': {'python': platform.python_version(), 'platform': platform.platform(),
                                            'processor': platform.processor() or 'not reported'},
                            'timing_scope': 'Local function calls including application logging; excludes writing exported reports to disk. ZIP hashing and proof-of-work are separate.',
                            'metrics': metrics}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    with (output / 'timings.csv').open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=['run', 'operation', 'seconds'])
        writer.writeheader()
        writer.writerows(rows)
    lines = ['# Three-scenario validation', '',
             f'Runs: {runs}. All functional checks passed in every run: {all(run_checks)}.', '',
             'Synthetic fixtures only. These are new measurements, not a reconstruction of historical measurements.', '',
             '## Functional checks', '']
    lines += [f'- {name}: {"PASS" if passed else "FAIL"}' for name, passed in summary['checks'].items()]
    lines += ['', '## Measured local timings', '', '| Operation | Samples | Median ms | p95 ms | Max ms | Report target ms | All below target |',
              '| --- | ---: | ---: | ---: | ---: | ---: | --- |']
    for name, m in metrics.items():
        target = m['dissertation_target_seconds']
        lines.append(f"| {name} | {m['samples']} | {m['median_seconds']*1000:.4f} | {m['p95_seconds']*1000:.4f} | {m['max_seconds']*1000:.4f} | {target*1000 if target else 'Not specified'} | {m['all_samples_under_target'] if target else 'N/A'} |")
    lines += ['', 'Environment: ' + json.dumps(summary['benchmark']['environment']), '',
              summary['benchmark']['timing_scope'], '',
              'A passing timing comparison applies only to this host and these tiny synthetic fixtures. It is not a Fabric, production, evidence-acquisition or scalability benchmark.', '',
              'Five-block schedule: genesis; phishing registration; phishing final snapshot; identity registration + final snapshot; breach registration + final snapshot.', '',
              'Identity history has exactly eight actions because the runner does not invoke the history-view operation.', '',
              'The demonstration parses synthetic exports. It does not run UFED, attribute Tor nodes, prove SQL injection exploitation, or contain 50000 customer records.', '',
              'Legal tags remain illustrative. The dissertation\'s BSA 65A/65B labels are not copied into these scenarios. Certificates are demonstration templates.']
    (output / 'RESULTS.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f"{'PASS' if all(run_checks) else 'FAIL'}: {runs} runs; 3 scenarios; 5 blocks; 4 access rejections.")
    print(f'Reports and measured timings: {output}')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=int, default=20)
    parser.add_argument('--output', type=Path, default=ROOT / 'scenario_output')
    args = parser.parse_args()
    result = benchmark(args.runs, args.output)
    raise SystemExit(0 if result['benchmark']['all_runs_passed'] else 1)
