# Test NyayaChain with your own evidence

Run the normal application, not just the scenario demonstration:

```bash
python nyayachain_dissertation.py
```

## Full user-entered case

1. Log in as police `P001` (`Police@2025`). Register your case and evidence using option **1**. Use a local export, ZIP, or an HTTP/HTTPS URL. Note the evidence ID. File bytes are hashed during registration.
2. Transfer custody to `L001` with police option **2**. Create a lab request using option **5**. Enter your own examination targets, such as “Count failed login events and identify their source IPs.”
3. Log out and return to login without closing the process. Sign in as lab `L001` (`Lab@2025`). Use lab option **2** to acknowledge the request.
4. Use lab option **3** to select a target. Choose analysis mode **1** to derive observations from evidence, then choose the relevant profile. Leave the local-copy prompt blank to read the registered location. If that location is unavailable, supply an identical local copy; its SHA-256 must match the registered fingerprint.
5. Read the computed observations and limitations. Choose RESOLVED only if they answer the target; choose IN_PROGRESS or UNABLE_TO_DETERMINE where appropriate. Unsupported/unmatched input is marked MANUAL_EXAMINATION_REQUIRED and is not automatically resolved. Use manual mode **2** to record a qualified examiner's findings from external tools.
6. Repeat for each target. The request closes when every finding is resolved or unable to determine; each individual outcome remains visible. Transfer custody back using lab option **5** if your procedure requires it.
7. Log in as police. Use option **7** to tag the case and submit its final snapshot, then option **3** to mine it. Final submission rejects missing analysis, open requests or missing BNS tags.
8. Log in as court `C001` (`Court@2025`). View/export your case reports. Text reports print to the terminal, and JSON export saves a file. Procedure status shows whether requests closed and whether the final snapshot was mined. The generated certificate is a demonstration template.

For examination without a request, lab option **A** computes observations from registered evidence and offers to record them in its history. Court users cannot run laboratory analysis. All users must use the same running application: state is still in memory and is lost when it closes.

## Supported profiles and input schemas

CSV headings and JSON keys are matched without case sensitivity. Use UTF-8. JSON may contain a list of objects, one object, or an object with a `records` or `events` array. JSONL/NDJSON contains one object per line. TXT/LOG supports `key=value` event lines. ZIP files can contain several supported exports; members are read without extraction.

| Profile | Fields / format | Derived observations |
| --- | --- | --- |
| `email` | EML or text containing standard headers: Date, From, To, Message-ID, Received, X-Originating-IP, Authentication-Results | Header values, separated by source file |
| `authentication` | `user`/`username`/`account` and `result`/`status`/`outcome`; optional `source_ip`/`src_ip`/`ip`/`source` | Event, success/failure and other-outcome counts; users and IPs |
| `identity` | `imsi`, `imei`, `device`/`device_id`, `peer`, `caller`, `callee` | Observed identifiers and counts for device/peer or caller/callee pairs |
| `network` | `destination`/`dst_ip`/`dest_ip`; optional `bytes`/`size_bytes`/`bytes_sent`; web records: `path`/`url`/`request`/`query` | Destinations, valid byte totals, missing/invalid byte counts; simple SQL-like request markers |
| `inventory` | Any supported text/export file | Member name, byte count and parsed-row count; not an examination conclusion |

Recognized failed outcomes: FAILED, FAILURE, FAIL, DENIED, INVALID. Recognized successful outcomes: SUCCESS, SUCCESSFUL, ACCEPTED, OK. Other outcome strings remain visible in the counts but are not silently classified as success or failure.

Analysis is limited to a 10 MiB input, 100 ZIP members and 10 MiB total uncompressed ZIP contents. Encrypted ZIP members, malformed exports, binary PCAP, documents, registry hives and unsupported formats require manual examination or an external export to a supported schema. A successfully parsed file does not imply every field or event was understood.

## Quick proof that results depend on inputs

Use `examples/tester_inputs/authentication.csv` with profile `authentication`. Its initial observations contain **2 failures, 1 success and source IP 203.0.113.42**.

Make a copy, add another FAILED row and register that copy as new evidence. It will produce **3 failures and 1 success**. Changing the source IP changes the observed IP list. Editing a file after registration produces an integrity-mismatch error; the application does not silently analyze changed bytes.

Other synthetic tester files are provided for email, identity and network profiles. `network.csv` initially totals **350 bytes**. All are editable examples, not real investigation data.

## What results mean

Findings include the selected profile, registered evidence hash, source filenames/member hashes, computed observations, skipped files and parser limitations. They are recorded in linked history entries and included in custody/JSON reports and request briefs after examiner review.

Header extraction does not authenticate a sender. Repeated calls do not establish identity theft. Traffic volumes do not establish exfiltration or Tor attribution. SQL-like markers are review leads with potential false positives/negatives; they do not prove exploitation. No UFED tool, packet parser or general malware/document analysis engine is included.

## Automated checks

```bash
python -m unittest discover -s tests -v
python scenarios.py --runs 20
```

Tests use different uploaded event counts, changed evidence, mixed ZIP exports and the actual terminal finding-response function to confirm that findings come from entered bytes. The scenario runner now uses the same parser instead of fixed analysis narratives.
