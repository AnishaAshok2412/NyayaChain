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
| ZIP file hashing (separate from registration) | 60 | 0.0693 | 0.1196 | 0.1418 | Not specified | N/A |
| Evidence registration | 60 | 0.1558 | 0.3216 | 2.8100 | 100.0 | True |
| Proof-of-work mining (separate) | 80 | 34.4311 | 140.3905 | 245.7542 | Not specified | N/A |
| Custody transfer logging | 80 | 0.0198 | 0.0655 | 0.1186 | 100.0 | True |
| Lab request issuance | 20 | 0.0770 | 0.1204 | 0.1391 | 100.0 | True |
| Evidence parsing (separate) | 100 | 0.3199 | 0.9467 | 3.0241 | Not specified | N/A |
| Finding response logging | 40 | 0.0641 | 0.1164 | 0.1879 | Not specified | N/A |
| Legal mapping | 60 | 0.0177 | 0.0228 | 0.0354 | Not specified | N/A |
| Final snapshot submission | 60 | 0.1602 | 0.2884 | 0.3268 | Not specified | N/A |
| Analysis action logging | 80 | 0.0303 | 0.0409 | 0.0701 | 100.0 | True |
| History report generation (8+ actions) | 40 | 0.5080 | 0.7703 | 2.0668 | 500.0 | True |
| Demonstration certificate generation | 60 | 0.3226 | 0.4175 | 0.6399 | 200.0 | True |
| JSON report generation | 60 | 0.4658 | 0.8386 | 1.0398 | 300.0 | True |
| History report generation (<8 actions) | 20 | 0.3395 | 0.4223 | 0.4256 | Not specified | N/A |

Environment: {"python": "3.12.14", "platform": "Linux-6.18.55-x86_64-with-glibc2.39", "processor": "x86_64"}

Local function calls including application logging; excludes writing exported reports to disk. ZIP hashing and proof-of-work are separate.

A passing timing comparison applies only to this host and these tiny synthetic fixtures. It is not a Fabric, production, evidence-acquisition or scalability benchmark.

Five-block schedule: genesis; phishing registration; phishing final snapshot; identity registration + final snapshot; breach registration + final snapshot.

Identity history has exactly eight actions because the runner does not invoke the history-view operation.

The demonstration parses synthetic exports. It does not run UFED, attribute Tor nodes, prove SQL injection exploitation, or contain 50000 customer records.

Legal tags remain illustrative. The dissertation's BSA 65A/65B labels are not copied into these scenarios. Certificates are demonstration templates.
