"""Run a synthetic end-to-end case and export demonstration reports."""
import json
from pathlib import Path
import nyayachain_dissertation as n


def run_demo(output_dir=None):
    bc = n.MetadataBlockchain()
    police, lab, court = (n.SEED_USERS[k] for k in ('P001', 'L001', 'C001'))
    meta = n.ingest_offchain_evidence(str(Path(__file__).parent / 'examples' / 'auth_log.txt'))
    eid = bc.add_evidence_record(police, police.name, police.badge_id, 'DEMO-001',
        'Synthetic authentication event investigation', 'Sample authentication log',
        'log', 'Cyber Fraud / Cheating Online (Sec. 318)', meta,
        'Demo workstation', 'Demo forensic lab')
    bc.transfer_custody(police, eid, lab, 'Synthetic forensic examination')
    request = bc.issue_lab_request(police, 'DEMO-001', 'Examine synthetic authentication events',
        [{'evidence_id': eid, 'description': 'Identify failed and successful logins', 'priority': 'MEDIUM'}])
    bc.acknowledge_lab_request(lab, request.request_id)
    bc.respond_to_finding(lab, request.request_id, request.findings[0].finding_id,
        'One failed login followed by one successful login in the synthetic log.',
        n.FindingStatus.RESOLVED, 'Log review', 'Manual text inspection')
    bc.transfer_custody(lab, eid, police, 'Examination completed')
    # Illustrative project configuration, not a verified legal assessment.
    bc.map_legal_sections(police, eid, ['Sec. 318(4)'], [], [], [])
    bc.commit_evidence_to_blockchain(police, eid)
    bc.mine_block(police)
    bc.view_history(court, eid)
    reporter = n.ReportGenerator(bc)
    reports = {'evidence_report.txt': reporter.text_report(court, eid),
               'evidence_report.json': reporter.json_report(court, eid),
               'lab_findings.txt': reporter.lab_request_report(court, request.request_id),
               'demo_certificate.txt': reporter.bsa_certificate(court, eid)}
    if output_dir:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        for name, content in reports.items():
            (output / name).write_text(content, encoding='utf-8')
    report = json.loads(reports['evidence_report.json'])
    assert report['integrity']['history_chain_valid']
    assert report['integrity']['block_chain_valid']
    print('PASS: end-to-end workflow, encrypted snapshot, reports and integrity checks.')
    return bc, eid, reports


if __name__ == '__main__':
    run_demo(Path(__file__).parent / 'demo_output')
