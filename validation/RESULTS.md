# Three-scenario validation

Runs: 20. All functional checks passed in every run: True.

Synthetic fixtures only. These are new measurements, not a reconstruction of historical measurements.

## Functional checks

- three_cases_registered: PASS
- five_blocks: PASS
- six_snapshots_mined: PASS
- no_pending_snapshots: PASS
- two_phishing_findings_resolved: PASS
- phishing_request_completed: PASS
- identity_eight_action_sequence: PASS
- data_breach_two_analysis_entries: PASS
- all_histories_valid: PASS
- block_chain_valid: PASS
- four_access_rejections_without_mutation: PASS
- history_tamper_detected: PASS
- block_tamper_detected: PASS
- encrypted_final_snapshots_match: PASS
- evidence_file_hashes_match: PASS

## Measured local timings

| Operation | Samples | Median ms | p95 ms | Max ms | Report target ms | All below target |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| ZIP file hashing (separate from registration) | 60 | 0.0778 | 0.1159 | 0.1820 | Not specified | N/A |
| Evidence registration | 60 | 0.1436 | 0.3140 | 2.8141 | 100.0 | True |
| Proof-of-work mining (separate) | 80 | 28.4636 | 115.2181 | 190.4825 | Not specified | N/A |
| Custody transfer logging | 80 | 0.0182 | 0.0658 | 0.1288 | 100.0 | True |
| Lab request issuance | 20 | 0.0746 | 0.0885 | 0.0930 | 100.0 | True |
| Finding response logging | 40 | 0.0334 | 0.0553 | 0.1094 | Not specified | N/A |
| Legal mapping | 60 | 0.0155 | 0.0668 | 0.2201 | Not specified | N/A |
| Final snapshot submission | 60 | 0.1322 | 0.2392 | 0.4571 | Not specified | N/A |
| Analysis action logging | 80 | 0.0144 | 0.0286 | 0.0767 | 100.0 | True |
| History report generation (8+ actions) | 40 | 0.4513 | 0.7093 | 0.7486 | 500.0 | True |
| Demonstration certificate generation | 60 | 0.2817 | 0.4115 | 0.5711 | 200.0 | True |
| JSON report generation | 60 | 0.4547 | 0.6951 | 0.9073 | 300.0 | True |
| History report generation (<8 actions) | 20 | 0.2699 | 0.4609 | 0.5454 | Not specified | N/A |

Environment: {"python": "3.12.14", "platform": "Linux-6.18.55-x86_64-with-glibc2.39", "processor": "x86_64"}

Local function calls including application logging; excludes writing exported reports to disk. ZIP hashing and proof-of-work are separate.

A passing timing comparison applies only to this host and these tiny synthetic fixtures. It is not a Fabric, production, evidence-acquisition or scalability benchmark.

Five-block schedule: genesis; phishing registration; phishing final snapshot; identity registration + final snapshot; breach registration + final snapshot.

Identity history has exactly eight actions because the runner does not invoke the history-view operation.

The demonstration records supplied examiner findings. It does not run UFED, identify Tor nodes, detect SQL injection, or contain 50000 customer records.

Legal tags remain illustrative. The dissertation's BSA 65A/65B labels are not copied into these scenarios. Certificates are demonstration templates.
