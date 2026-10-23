# Preparation changes

The supplied dissertation source remains the main application, with these focused changes:

- Fixed User-object access in history displays and evidence/lab reports.
- Added proof-of-work validation to the existing block-link verification.
- Corrected the exit message: the in-memory ledger is discarded on exit.
- Marked demonstration certificate/report headings as academic templates.
- Added dependencies, synthetic evidence, an automated demo, workflow regression checks and setup/GitHub instructions.

Legal catalogues and the core workflow have not been independently validated or redesigned. See README limitations.

## Dissertation scenario reproduction

- Added `scenarios.py` for all three synthetic Chapter 6 workflows.
- Added two phishing findings, the exact eight-action identity history and the five-block mining schedule.
- Added four access-denial checks, hash/snapshot verification and tampering checks.
- Added repeated timings, raw CSV samples, environment details and comparisons with the dissertation's stated timing thresholds.
- Added exported case reports, stable synthetic ZIP fixtures and integration coverage.
- Kept forensic conclusions labelled as example examiner entries and retained certificate/legal limitations.

## Data-derived interactive findings

- Added bounded CSV/JSON/JSONL, key=value text-log and email-header parsers for local, ZIP and HTTP/HTTPS evidence.
- Verify registered SHA-256 before computing observations; require manual examination for unsupported/unmatched evidence.
- Integrated analysis into lab finding responses and new lab menu A; examiner reviews outcomes before recording.
- Added request acknowledgement/assigned-examiner checks and final-submission prerequisites.
- Added procedure status to case reports, including unresolved/indeterminate findings and actual final-snapshot mining.
- Updated both demos to derive observations from evidence rather than fixed analysis narratives.
- Added tester input samples, TESTING.md and integration tests for different input data.
