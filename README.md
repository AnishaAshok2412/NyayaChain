# NyayaChain

**Master’s final-year project — Anisha Ashok**

## Blockchain-Based Platform for Forensic Investigation of Metadata-Centric Digital Evidence

A Python command-line academic prototype for evidence registration, forensic laboratory requests, chain-of-custody tracking, illustrative legal-section tagging, encrypted metadata snapshots and report generation. Evidence content stays off-chain; file locations, SHA-256 fingerprints and size are stored as metadata.

## Features

- Police, forensic-lab and court-viewer roles.
- Evidence classification and configurable evidence-type/section matching.
- Local file, ZIP, directory and HTTP/HTTPS evidence hashing.
- Linked custody and analysis histories.
- Lab requests, finding priorities, acknowledgements and responses.
- AES-CBC encrypted snapshots with PyCryptodome installed.
- Local proof-of-work blocks and integrity verification.
- Text, JSON, lab findings and demonstration certificate reports.

## Quick start — macOS / Linux

Use Python 3.10 or newer. Open Terminal inside this project folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python demo.py
```

The demo runs a synthetic case from registration through laboratory examination, custody return, final snapshot creation, mining and reporting. Four report files are written to `demo_output/`.

For Windows PowerShell use `.venv\Scripts\Activate.ps1` to activate the environment.

Start the interactive application:

```bash
python nyayachain_dissertation.py
```

## Demo accounts

| Role | User ID | Demo password |
| --- | --- | --- |
| Police | P001 | Police@2025 |
| Forensic laboratory | L001 | Lab@2025 |
| Court viewer | C001 | Court@2025 |

These are intentionally public demonstration accounts.

## Interactive walkthrough

1. Log in as `P001`. Select **1** to register evidence. The synthetic file `examples/auth_log.txt` is provided. Choose evidence type `log` and a compatible category such as the project's cyber-fraud/cheating category. Record the generated evidence ID.
2. Select **2** to transfer custody to `L001`, then **5** to issue a laboratory request with a finding target.
3. Log out, answer `y` to return to login, and sign in as `L001`. Select **2** to acknowledge the request and **3** to respond to its finding. Select **5** to return custody to `P001`.
4. Return to login as `P001`. Select **7** for illustrative legal tagging and final snapshot creation, then **3** to mine pending snapshots.
5. Sign in as `C001` to view histories and generate reports. JSON export saves a file; text reports print to the terminal. `demo.py` saves every report type to files.
6. Export reports before closing. All roles share cases only within the same running process.

## Files

| File | Purpose |
| --- | --- |
| `nyayachain_dissertation.py` | Main interactive application and domain model |
| `demo.py` | Automated synthetic case |
| `examples/auth_log.txt` | Synthetic example evidence |
| `tests/test_workflow.py` | Workflow and regression checks |
| `requirements.txt` | Tested direct dependencies |
| `CHANGELOG.md` | Preparation changes |

## Verification

```bash
python -m unittest discover -s tests -v
```

Tested with Python 3.12. The integration test exercises registration, transfers, request completion, final snapshot mining, all report types, AES decryption, denied court mining, invalid type/section matching, transaction tampering and invalid proof detection. Interactive police login/logout was also verified.

## Scope and limitations

This is a single-process Python blockchain simulation, not a deployed Hyperledger Fabric network. Source comments compare components conceptually; Fabric does not use this prototype's proof-of-work scheme. There are no distributed peers, deployed chaincodes, certificate authorities or real smart contracts.

The ledger disappears when the process ends. Registration and final-commit snapshots are queued for mining; intermediate actions live in mutable in-memory histories and appear in later snapshots. Final-commit status means snapshot submission; mining is separate. Viewing history appends a view event. There is no trusted external checkpoint preventing someone controlling the process from rebuilding its chain.

Public demo passwords, a hard-coded demo AES key, unauthenticated CBC encryption and optional plaintext fallback are retained from the supplied prototype. Role checks are illustrative; custody ownership, case isolation and workflow sequencing are not comprehensively enforced. URL hashing does not preserve a downloaded copy. Directory ingestion can reuse an existing sibling ZIP; create a fresh ZIP to demonstrate changed evidence.

Legal catalogues, punishment descriptions and evidence-type mappings came from the supplied dissertation source and have not been legally verified. They are demonstration configuration, not statutory restrictions on evidence types. Generated reports and certificate IDs do not establish legal compliance or admissibility; the certificate is not an official statutory form. Use synthetic data for this portfolio demonstration.

No performance or compliance percentages are claimed without a separate documented evaluation.

## GitHub setup

Suggested repository name: `NyayaChain`

Suggested description: Master's final-year project: Python blockchain prototype for metadata-centric digital evidence, chain of custody and forensic lab workflows.

Create an empty GitHub repository, then upload the project contents with README at the repository root. Include the `examples` and `tests` folders. Exclude `.venv`, caches, real evidence and generated reports.

Alternatively, with Git installed, replace `YOUR_USERNAME` below:

```bash
git init -b main
git add README.md CHANGELOG.md requirements.txt .gitignore nyayachain_dissertation.py demo.py examples tests
git commit -m "Add master's final-year NyayaChain project"
git remote add origin https://github.com/YOUR_USERNAME/NyayaChain.git
git push -u origin main
```

Suggested topics: `python`, `digital-forensics`, `blockchain`, `chain-of-custody`, `cybersecurity`, `academic-project`.
