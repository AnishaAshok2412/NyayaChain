"""
nyayachain_dissertation.py
══════════════════════════════════════════════════════════════════════════════
NyayaChain — Blockchain-Based Platform for Forensic Investigation of
             Metadata-Centric Digital Evidence

Dissertation Final Submission
══════════════════════════════════════════════════════════════════════════════

DESIGN OVERVIEW
───────────────
This prototype implements the complete blockchain pipeline described in the
dissertation, covering:

  Phase 1  →  Police: Crime-scene seizure, evidence registration, lab request
  Phase 2  →  Forensic Lab: Acknowledge request, analyse evidence, respond
  Phase 3  →  Investigating Officer: Legal-section mapping, blockchain commit
  Court    →  Read-only chain-of-custody and BSA certificate reports

LEGAL FRAMEWORK INTEGRATED
───────────────────────────
  • BNS 2023  (Bharatiya Nyaya Sanhita)
  • BNSS 2023 (Bharatiya Nagarik Suraksha Sanhita)
  • BSA 2023  (Bharatiya Sakshya Adhiniyam)
  • IT Act 2000 / 2008

HYPERLEDGER FABRIC MAPPING
───────────────────────────
  MetadataBlockchain.world_state   → World State (CouchDB / LevelDB)
  EvidenceRecord                   → World State Asset / Chaincode Object
  LabRequest                       → World State Asset  (key = request_id)
  FindingTarget                    → Nested object inside LabRequest state
  ActionEntry                      → Transaction (Block payload)
  ActionEntry.entry_hash           → Transaction ID / Block Hash (SHA-256)
  bc.chain                         → Blockchain log (orderer + peer replicas)
  bc.pending                       → Transaction pool (pre-commit mempool)
  add_evidence_record()            → Chaincode: RegisterEvidence()
  transfer_custody()               → Chaincode: TransferCustody()
  log_analysis()                   → Chaincode: LogAnalysis()
  view_history()                   → Chaincode: GetHistoryForKey()
  mine_block() + proof_of_work()   → Orderer consensus + block commit (PoW)
  issue_lab_request()              → Chaincode: IssueLabRequest()
  acknowledge_lab_request()        → Chaincode: AcknowledgeRequest()
  respond_to_finding()             → Chaincode: RespondToFinding()
  ROLE_PERMISSIONS dict            → Endorsement Policy / ABAC rules
  User.role                        → x.509 certificate OU attribute (MSP)
  ReportGenerator                  → Off-chain application / REST gateway
  _verify_history_chain()          → Peer block validation + gossip protocol
  AES-CBC encrypted records        → Private data collections (Fabric PDC)

REQUIREMENTS
────────────
  Python 3.10+
  pip install pycryptodome        (for AES encryption — optional but recommended)

  Run:  python nyayachain_dissertation.py
"""

# ══════════════════════════════════════════════════════════════════════════════
# Standard library imports
# ══════════════════════════════════════════════════════════════════════════════
import hashlib
import json
import os
import sys
import uuid
import zipfile
from evidence_analysis import analyze_evidence, format_analysis
from base64 import b64decode, b64encode
from datetime import datetime, timezone
from enum import Enum
from time import time
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
# Optional third-party imports
# ══════════════════════════════════════════════════════════════════════════════
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    _AES_AVAILABLE = True
except ImportError:
    _AES_AVAILABLE = False
    print("[WARN] PyCryptodome not installed — AES encryption disabled (fallback mode).")
    print("       Install with:  pip install pycryptodome\n")

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CONSTANTS & CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# ── Evidence types (metadata-centric only) ────────────────────────────────────
EVIDENCE_TYPES = [
    'log',            # System / application / audit logs
    'text',           # Plain text files, chat exports
    'document',       # PDF, DOCX, spreadsheets
    'metadata',       # EXIF, timestamps, geo-location, hashes
    'system_file',    # Registry hives, config files, OS artefacts
    'network_trace',  # PCAP, NetFlow exports
    'device_id',      # IMEI, MAC address, device identifiers
    'comm_record',    # Call logs, IMSI/SS7 records, email headers
    'db_entry',       # Exported DB rows, SQL dumps, snapshots
]

# ── BNS Section → allowed evidence types mapping ─────────────────────────────
BNS_EVIDENCE_MAP = {
    'Organised crime (Sec. 111)':              ['log', 'network_trace', 'document', 'metadata', 'device_id', 'db_entry'],
    'Petty organised crime (Sec. 112)':        ['log', 'document', 'metadata', 'device_id'],
    'Terrorist act (Sec. 113)':                ['log', 'network_trace', 'document', 'metadata', 'device_id'],
    'Cyber Fraud / Cheating Online (Sec. 318)':['log', 'network_trace', 'document', 'metadata', 'db_entry', 'comm_record'],
    'Data Breach / Unauthorised Access':       ['log', 'network_trace', 'document', 'metadata', 'db_entry'],
    'Phishing / Online Fraud':                 ['log', 'network_trace', 'document', 'metadata', 'comm_record'],
    'Digital Theft (Sec. 303/316/317)':        ['log', 'metadata', 'device_id', 'document'],
    'Robbery (Sec. 309)':                      ['log', 'metadata', 'device_id'],
    'Extortion (Sec. 308)':                    ['comm_record', 'document', 'log', 'metadata'],
    'Criminal Breach of Trust (Sec. 316)':     ['document', 'log', 'db_entry', 'metadata'],
    'Trafficking of Persons (Sec. 143)':       ['document', 'comm_record', 'metadata', 'log'],
    'Act Endangering Sovereignty (Sec. 152)':  ['document', 'log', 'metadata', 'comm_record'],
    'Forgery of Electronic Record (Sec. 336)': ['document', 'metadata', 'log'],
    'Cheating by Personation (Sec. 319)':      ['log', 'metadata', 'comm_record', 'document'],
    'Cyberstalking / Voyeurism (Sec. 77/78)':  ['comm_record', 'metadata', 'log'],
    'Conspiracy / Attempt (Sec. 61/62)':       ['document', 'log', 'metadata', 'db_entry'],
    'Criminal Intimidation (Sec. 351)':        ['comm_record', 'document', 'log', 'metadata'],
}
BNS_SECTIONS = sorted(BNS_EVIDENCE_MAP.keys())

# ── Legal sections for Phase-3 mapping ───────────────────────────────────────
BNS_CYBER_LAWS = [
    {'code': 'Sec. 111(1)',    'title': 'Organised Crime',              'note': 'Any continuing unlawful activity including cyber-crimes by a person or group.', 'punishment': 'Min 5 years to life + fine (min ₹5 lakh).'},
    {'code': 'Sec. 111(3)',    'title': 'Abetment of Organised Crime',  'note': 'Abetting, attempting, or conspiring to facilitate organised crime.',             'punishment': 'Min 5 years to life + fine (min ₹5 lakh).'},
    {'code': 'Sec. 112(1)',    'title': 'Petty Organised Crime',        'note': 'Theft via card skimming, ATM theft, trick theft by gang member.',                'punishment': '1 to 7 years imprisonment + fine.'},
    {'code': 'Sec. 303/316',   'title': 'Digital Theft',                'note': 'Theft of mobile phones, data, software or hardware.',                            'punishment': 'As per BNS 2023 provisions.'},
    {'code': 'Sec. 318(4)',    'title': 'Cheating (Electronic)',         'note': 'Dishonestly inducing delivery of property via digital means.',                   'punishment': 'Up to 7 years + fine.'},
    {'code': 'Sec. 319(1)',    'title': 'Cheating by Personation',      'note': 'Pretending to be another person or substituting identity digitally.',            'punishment': 'Up to 5 years or fine.'},
    {'code': 'Sec. 336(1)',    'title': 'Forgery (Electronic Record)',   'note': 'Making false electronic record with intent to defraud.',                        'punishment': 'Up to 2 years or fine.'},
    {'code': 'Sec. 336(3)',    'title': 'Forgery for Cheating',          'note': 'Forgery intending electronic record to be used for cheating.',                  'punishment': 'Up to 7 years + fine.'},
    {'code': 'Sec. 337',       'title': 'Forgery of Court/Public Record','note': 'Forging record of Court or identity document (Aadhaar/Voter ID).',             'punishment': 'Up to 7 years + fine.'},
    {'code': 'Sec. 77',        'title': 'Voyeurism',                    'note': 'Capturing or disseminating private image of woman (cyber voyeurism).',          'punishment': '1st conviction: 1–3 years + fine.'},
    {'code': 'Sec. 78',        'title': 'Cyberstalking',                 'note': 'Electronic harassment or stalking of a woman via digital means.',               'punishment': 'As per BNS 2023 provisions.'},
]

BNSS_SECTIONS_LIST = [
    {'code': 'Sec. 91/93/94/100/165', 'title': 'Search & Seizure Warrants',       'note': 'Warrants for search, production, or seizure of electronic records.'},
    {'code': 'Sec. 105',              'title': 'Mandatory AV Recording',           'note': 'Mandatory audio-video recording of search/seizure of electronic devices.'},
    {'code': 'Sec. 105A/105B',        'title': 'Digital Evidence Attachment',      'note': 'Procedure for attachment and custody of digital evidence during trial.'},
    {'code': 'Sec. 107',              'title': 'Chain-of-Custody Maintenance',     'note': 'Chain-of-custody maintenance for transferred evidence.'},
]

BSA_SECTIONS_LIST = [
    {'code': 'Sec. 2(1)(d)',  'title': 'Definition of Documents',         'note': 'Defines documents to include electronic and digital records.'},
    {'code': 'Sec. 59–63',    'title': 'Primary Evidence Conditions',     'note': 'Electronic records as primary evidence; authenticity conditions.'},
    {'code': 'Sec. 61',       'title': 'Admissibility of Digital Content','note': 'Admissibility of digital content irrespective of medium.'},
    {'code': 'Sec. 63',       'title': 'Validity Certificates',           'note': 'Certificates for validity of electronic data (Part A/B forms).'},
    {'code': 'Sec. 65A–65B',  'title': 'Computer-Generated Evidence',     'note': 'Conditions for admissibility of computer-generated evidence.'},
]

IT_ACT_LIST = [
    {'code': 'Sec. 2(1)(r)/(t)', 'title': 'Definitions',                   'note': 'Digital signature and electronic record definitions.'},
    {'code': 'Sec. 43/43A',      'title': 'Data Theft & Protection',        'note': 'Data theft, unauthorised access, and compensation for failures.'},
    {'code': 'Sec. 65',          'title': 'Tampering',                      'note': 'Tampering with source code or digital evidence.'},
    {'code': 'Sec. 66/66B–F',    'title': 'Identity Theft & Cyber Terrorism','note': 'Identity theft, impersonation, privacy violations, cyber terrorism.'},
    {'code': 'Sec. 67/67A/67B',  'title': 'Obscene Material',              'note': 'Publication or circulation of offensive digital material.'},
    {'code': 'Sec. 69/69A/69B',  'title': 'Govt Regulatory Access',        'note': 'Interception, decryption, and government regulatory access.'},
    {'code': 'Sec. 79/79A',      'title': 'Intermediary Liability',         'note': 'Intermediary liability and certification authority for forensics.'},
]

# ── Demo credentials (replace with PKI / HSM in production) ──────────────────
AES_KEY     = b'mysecretpassword'   # 16-byte AES key — demo only
DEMO_KEYS   = {
    'police':       'Police@2025',
    'forensic_lab': 'Lab@2025',
    'court_viewer': 'Court@2025',
}


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — ENUMERATIONS
# ══════════════════════════════════════════════════════════════════════════════

class Role(str, Enum):
    """
    Fabric mapping: x.509 certificate OU attribute.
    Each role maps to a separate MSP or OU in a real deployment.
    """
    POLICE       = 'police'
    FORENSIC_LAB = 'forensic_lab'
    COURT_VIEWER = 'court_viewer'


class ActionType(str, Enum):
    """Each ActionType maps to a named chaincode function / transaction type."""
    REGISTER           = 'REGISTER'
    TRANSFER_CUSTODY   = 'TRANSFER_CUSTODY'
    LOG_ANALYSIS       = 'LOG_ANALYSIS'
    VIEW_HISTORY       = 'VIEW_HISTORY'
    EXPORT_REPORT      = 'EXPORT_REPORT'
    MINE_BLOCK         = 'MINE_BLOCK'
    ISSUE_LAB_REQUEST  = 'ISSUE_LAB_REQUEST'
    ACK_LAB_REQUEST    = 'ACK_LAB_REQUEST'
    RESPOND_TO_FINDING = 'RESPOND_TO_FINDING'
    LEGAL_MAPPING      = 'LEGAL_MAPPING'
    BLOCKCHAIN_COMMIT  = 'BLOCKCHAIN_COMMIT'


class Priority(str, Enum):
    LOW      = 'LOW'
    MEDIUM   = 'MEDIUM'
    HIGH     = 'HIGH'
    CRITICAL = 'CRITICAL'


class FindingStatus(str, Enum):
    PENDING             = 'PENDING'
    IN_PROGRESS         = 'IN_PROGRESS'
    RESOLVED            = 'RESOLVED'
    UNABLE_TO_DETERMINE = 'UNABLE_TO_DETERMINE'


class RequestStatus(str, Enum):
    ISSUED       = 'ISSUED'
    ACKNOWLEDGED = 'ACKNOWLEDGED'
    IN_PROGRESS  = 'IN_PROGRESS'
    COMPLETED    = 'COMPLETED'
    WITHDRAWN    = 'WITHDRAWN'


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — ROLE PERMISSIONS  (Endorsement Policy stub)
# ══════════════════════════════════════════════════════════════════════════════

ROLE_PERMISSIONS: dict = {
    Role.POLICE: {
        ActionType.REGISTER,
        ActionType.TRANSFER_CUSTODY,
        ActionType.VIEW_HISTORY,
        ActionType.EXPORT_REPORT,
        ActionType.MINE_BLOCK,
        ActionType.ISSUE_LAB_REQUEST,
        ActionType.LEGAL_MAPPING,
        ActionType.BLOCKCHAIN_COMMIT,
    },
    Role.FORENSIC_LAB: {
        ActionType.LOG_ANALYSIS,
        ActionType.TRANSFER_CUSTODY,
        ActionType.VIEW_HISTORY,
        ActionType.EXPORT_REPORT,
        ActionType.ACK_LAB_REQUEST,
        ActionType.RESPOND_TO_FINDING,
    },
    Role.COURT_VIEWER: {
        ActionType.VIEW_HISTORY,
        ActionType.EXPORT_REPORT,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — IDENTITY MODEL
# ══════════════════════════════════════════════════════════════════════════════

class User:
    """
    Fabric mapping: Enrolled MSP identity.
    In Hyperledger Fabric this is an x.509 certificate issued by the
    Organisation CA with OU=<role>.
    """
    def __init__(self, user_id: str, name: str, role: Role,
                 organisation: str, badge_id: str = ''):
        self.user_id      = user_id
        self.name         = name
        self.role         = role
        self.organisation = organisation
        self.badge_id     = badge_id or user_id

    def __repr__(self):
        return f"User({self.name!r}, role={self.role.value})"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — TRANSACTION / ACTION ENTRY
# ══════════════════════════════════════════════════════════════════════════════

class ActionEntry:
    """
    Fabric mapping:
      One ActionEntry = one transaction recorded on the ledger.
        tx_id         → TXID
        timestamp     → tx header timestamp
        actor         → tx.creator (MSP identity)
        action_type   → chaincode function name
        payload       → input arguments / write-set
        prev_hash     → previous entry hash (chain linkage)
        entry_hash    → this entry's SHA-256 fingerprint
    """
    def __init__(self, actor: User, action_type: ActionType, payload: dict,
                 prev_hash: str = 'GENESIS'):
        self.tx_id       = str(uuid.uuid4())
        self.timestamp   = datetime.now(timezone.utc).isoformat()
        self.actor       = actor
        self.action_type = action_type
        self.payload     = payload
        self.prev_hash   = prev_hash
        self.entry_hash  = self._compute_hash()

    def _compute_hash(self) -> str:
        canonical = json.dumps({
            'tx_id':       self.tx_id,
            'timestamp':   self.timestamp,
            'actor_id':    self.actor.user_id,
            'action_type': self.action_type.value,
            'payload':     self.payload,
            'prev_hash':   self.prev_hash,
        }, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            'tx_id':       self.tx_id,
            'timestamp':   self.timestamp,
            'actor': {
                'user_id':      self.actor.user_id,
                'name':         self.actor.name,
                'role':         self.actor.role.value,
                'badge_id':     self.actor.badge_id,
                'organisation': self.actor.organisation,
            },
            'action_type': self.action_type.value,
            'payload':     self.payload,
            'prev_hash':   self.prev_hash,
            'entry_hash':  self.entry_hash,
        }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — FINDING TARGET  (line-item inside a LabRequest)
# ══════════════════════════════════════════════════════════════════════════════

class FindingTarget:
    """
    A single item in the police officer's forensic brief to the lab.
    Stored as a nested object inside the LabRequest world-state entry.
    Each state change produces a RESPOND_TO_FINDING transaction.
    """
    def __init__(self, finding_id: str, evidence_id: str,
                 target_description: str, priority: Priority):
        self.finding_id         = finding_id
        self.evidence_id        = evidence_id
        self.target_description = target_description
        self.priority           = priority
        self.status             = FindingStatus.PENDING
        self.lab_response: str  = ''
        self.analysis_type: str = ''
        self.tool_used: str     = ''
        self.resolved_by: Optional[str] = None
        self.resolved_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            'finding_id':         self.finding_id,
            'evidence_id':        self.evidence_id,
            'target_description': self.target_description,
            'priority':           self.priority.value,
            'status':             self.status.value,
            'lab_response':       self.lab_response,
            'analysis_type':      self.analysis_type,
            'tool_used':          self.tool_used,
            'resolved_by':        self.resolved_by,
            'resolved_at':        self.resolved_at,
        }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — LAB REQUEST  (formal Police → Lab brief)
# ══════════════════════════════════════════════════════════════════════════════

class LabRequest:
    """
    Formal request issued by a police officer to the forensic lab.
    Fabric mapping: World State asset (key = request_id).

    Chaincode equivalents:
      IssueLabRequest()    → creates this object
      AcknowledgeRequest() → ISSUED → ACKNOWLEDGED
      RespondToFinding()   → updates a FindingTarget
    """
    def __init__(self, request_id: str, issued_by: User, case_id: str,
                 context: str, deadline: Optional[str] = None):
        self.request_id  = request_id
        self.issued_by   = issued_by
        self.case_id     = case_id
        self.context     = context
        self.deadline    = deadline or 'Not specified'
        self.status      = RequestStatus.ISSUED
        self.assigned_to: Optional[User] = None
        self.findings: list[FindingTarget] = []
        self.history:   list[ActionEntry]  = []
        self.created_at  = datetime.now(timezone.utc).isoformat()

    def add_finding_target(self, evidence_id: str, description: str,
                           priority: Priority = Priority.MEDIUM) -> FindingTarget:
        ft = FindingTarget(
            finding_id         = f'FT-{str(uuid.uuid4())[:6].upper()}',
            evidence_id        = evidence_id,
            target_description = description,
            priority           = priority,
        )
        self.findings.append(ft)
        return ft

    def get_finding(self, finding_id: str) -> Optional[FindingTarget]:
        for ft in self.findings:
            if ft.finding_id == finding_id:
                return ft
        return None

    def _last_hash(self) -> str:
        return self.history[-1].entry_hash if self.history else 'GENESIS'

    def append_action(self, entry: ActionEntry):
        self.history.append(entry)

    def _update_overall_status(self):
        statuses = {ft.status for ft in self.findings}
        if all(s in (FindingStatus.RESOLVED, FindingStatus.UNABLE_TO_DETERMINE)
               for s in statuses):
            self.status = RequestStatus.COMPLETED
        elif FindingStatus.IN_PROGRESS in statuses:
            self.status = RequestStatus.IN_PROGRESS

    def to_dict(self) -> dict:
        return {
            'request_id': self.request_id,
            'case_id':    self.case_id,
            'issued_by':  {
                'user_id':      self.issued_by.user_id,
                'name':         self.issued_by.name,
                'role':         self.issued_by.role.value,
                'badge_id':     self.issued_by.badge_id,
                'organisation': self.issued_by.organisation,
            },
            'assigned_to': {
                'user_id': self.assigned_to.user_id,
                'name':    self.assigned_to.name,
            } if self.assigned_to else None,
            'context':    self.context,
            'deadline':   self.deadline,
            'status':     self.status.value,
            'created_at': self.created_at,
            'findings':   [ft.to_dict() for ft in self.findings],
            'history':    [e.to_dict()  for e in self.history],
        }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — EVIDENCE RECORD  (World State entry)
# ══════════════════════════════════════════════════════════════════════════════

class EvidenceRecord:
    """
    Fabric mapping: One EvidenceRecord = one World State entry (key = evidence_id).
    history list mirrors GetHistoryForKey().

    Phase-3 addition:
      legal_sections — BNS / BNSS / BSA / IT Act sections mapped by IO.
      bsa_certificate_id — auto-generated court-admissibility certificate.
    """
    def __init__(self, evidence_id: str, officer: str, badge_id: str,
                 case_id: str, case_description: str,
                 summary: str, evidence_type: str, bns_section: str,
                 offchain_meta: dict, registered_by: User,
                 crime_scene_location: str = '', lab_location: str = ''):
        self.evidence_id          = evidence_id
        self.officer              = officer
        self.badge_id             = badge_id
        self.case_id              = case_id
        self.case_description     = case_description
        self.summary              = summary
        self.evidence_type        = evidence_type
        self.bns_section          = bns_section
        self.offchain_meta        = offchain_meta
        self.crime_scene_location = crime_scene_location
        self.lab_location         = lab_location
        self.current_holder       = registered_by
        self.status               = 'ACTIVE'
        self.lab_request_ids: list[str]   = []
        self.history:          list[ActionEntry] = []

        # Phase-3 — legal mapping fields
        self.legal_sections = {
            'bns':    [],
            'bnss':   [],
            'bsa':    [],
            'it_act': [],
        }
        self.bsa_certificate_id   = ''
        self.io_officer_name: str = ''
        self.io_officer_id: str   = ''
        self.committed_to_chain   = False
        self.committed_at: str    = ''

    def _last_hash(self) -> str:
        return self.history[-1].entry_hash if self.history else 'GENESIS'

    def append_action(self, entry: ActionEntry):
        self.history.append(entry)

    def to_dict(self) -> dict:
        return {
            'evidence_id':          self.evidence_id,
            'case_id':              self.case_id,
            'case_description':     self.case_description,
            'officer':              self.officer,
            'badge_id':             self.badge_id,
            'summary':              self.summary,
            'evidence_type':        self.evidence_type,
            'bns_section':          self.bns_section,
            'status':               self.status,
            'crime_scene_location': self.crime_scene_location,
            'lab_location':         self.lab_location,
            'current_holder': {
                'user_id':      self.current_holder.user_id,
                'name':         self.current_holder.name,
                'role':         self.current_holder.role.value,
                'organisation': self.current_holder.organisation,
            },
            'offchain_meta':      self.offchain_meta,
            'lab_request_ids':    self.lab_request_ids,
            'legal_sections':     self.legal_sections,
            'bsa_certificate_id': self.bsa_certificate_id,
            'io_officer_name':    self.io_officer_name,
            'io_officer_id':      self.io_officer_id,
            'committed_to_chain': self.committed_to_chain,
            'committed_at':       self.committed_at,
            'history':            [e.to_dict() for e in self.history],
        }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — AES HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def aes_encrypt_json(obj: dict) -> dict:
    """AES-CBC encrypt a JSON-serialisable object."""
    if not _AES_AVAILABLE:
        return {'plain': json.dumps(obj)}
    cipher    = AES.new(AES_KEY, AES.MODE_CBC)
    plaintext = json.dumps(obj, sort_keys=True).encode('utf-8')
    ct        = cipher.encrypt(pad(plaintext, AES.block_size))
    return {'iv': b64encode(cipher.iv).decode(), 'data': b64encode(ct).decode()}


def aes_decrypt_json(enc: dict) -> dict:
    if 'plain' in enc:
        return json.loads(enc['plain'])
    if not _AES_AVAILABLE:
        raise RuntimeError('PyCryptodome not installed; cannot decrypt.')
    iv     = b64decode(enc['iv'])
    ct     = b64decode(enc['data'])
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt     = unpad(cipher.decrypt(ct), AES.block_size)
    return json.loads(pt.decode('utf-8'))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — OFF-CHAIN EVIDENCE INGEST
# ══════════════════════════════════════════════════════════════════════════════

def ingest_offchain_evidence(evidence_location: str) -> dict:
    """
    Accepts an http/https URL or local file/directory path.
    Returns: {evidence_url, evidence_filename, evidence_hash, size_bytes, uploaded_at}
    """
    if evidence_location.startswith(('http://', 'https://')):
        if not _REQUESTS_AVAILABLE:
            raise RuntimeError('requests library not installed.')
        r = _requests.get(evidence_location, stream=True, timeout=30)
        r.raise_for_status()
        h, size = hashlib.sha256(), 0
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                size += len(chunk)
                h.update(chunk)
        return {
            'evidence_url':      evidence_location,
            'evidence_filename': os.path.basename(evidence_location.split('?')[0]),
            'evidence_hash':     h.hexdigest(),
            'size_bytes':        size,
            'uploaded_at':       time(),
        }

    if not os.path.exists(evidence_location):
        raise FileNotFoundError(f'Path not found: {evidence_location}')

    if os.path.isdir(evidence_location):
        parent   = os.path.dirname(os.path.abspath(evidence_location))
        base     = os.path.basename(os.path.abspath(evidence_location.rstrip(os.sep)))
        zip_name = os.path.join(parent, f'{base}.zip')
        if not os.path.exists(zip_name):
            with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(evidence_location):
                    for fname in files:
                        fp = os.path.join(root, fname)
                        zf.write(fp, os.path.relpath(fp, os.path.dirname(evidence_location)))
        size = os.path.getsize(zip_name)
        h    = hashlib.sha256()
        with open(zip_name, 'rb') as fh:
            for chunk in iter(lambda: fh.read(8192), b''): h.update(chunk)
        return {
            'evidence_url': zip_name, 'evidence_filename': os.path.basename(zip_name),
            'evidence_hash': h.hexdigest(), 'size_bytes': size, 'uploaded_at': time(),
        }

    if os.path.isfile(evidence_location):
        size = os.path.getsize(evidence_location)
        h    = hashlib.sha256()
        with open(evidence_location, 'rb') as fh:
            for chunk in iter(lambda: fh.read(8192), b''): h.update(chunk)
        return {
            'evidence_url':      os.path.abspath(evidence_location),
            'evidence_filename': os.path.basename(evidence_location),
            'evidence_hash':     h.hexdigest(),
            'size_bytes':        size,
            'uploaded_at':       time(),
        }

    raise RuntimeError('Unsupported evidence path type.')


def _stub_offchain_meta() -> dict:
    """Generate a demo stub when no real file is available."""
    stub_hash = hashlib.sha256(str(time()).encode()).hexdigest()
    return {
        'evidence_url':      'DEMO_STUB',
        'evidence_filename': 'demo_evidence_stub',
        'evidence_hash':     stub_hash,
        'size_bytes':        0,
        'uploaded_at':       time(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — PERMISSION HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _require_permission(actor: User, action: ActionType):
    if action not in ROLE_PERMISSIONS.get(actor.role, set()):
        allowed = [r.value for r, perms in ROLE_PERMISSIONS.items() if action in perms]
        raise PermissionError(
            f"Access denied: '{actor.role.value}' cannot perform '{action.value}'. "
            f"Allowed roles: {allowed}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — MAIN BLOCKCHAIN CLASS
# ══════════════════════════════════════════════════════════════════════════════

class MetadataBlockchain:
    """
    Core ledger and chaincode simulation.

    Fabric mapping:
      self.world_state   → World State (CouchDB/LevelDB)
      self.lab_requests  → World State — LabRequest assets
      self.chain         → Ordered block log (orderer + peer replicas)
      self.pending       → Pending transactions (mempool)
    """

    def __init__(self):
        self.chain:        list[dict]                 = []
        self.pending:      list[dict]                 = []
        self.world_state:  dict[str, EvidenceRecord]  = {}
        self.lab_requests: dict[str, LabRequest]      = {}
        self.new_block(proof=100, previous_hash='1')  # genesis block

    # ── Block operations ──────────────────────────────────────────────────────

    @staticmethod
    def hash(block: dict) -> str:
        return hashlib.sha256(
            json.dumps(block, sort_keys=True).encode('utf-8')
        ).hexdigest()

    @property
    def last_block(self) -> dict:
        return self.chain[-1]

    def new_block(self, proof: int, previous_hash: str = None) -> dict:
        block = {
            'index':         len(self.chain) + 1,
            'timestamp':     datetime.now(timezone.utc).isoformat(),
            'records':       self.pending,
            'proof':         proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.pending = []
        self.chain.append(block)
        print(f"  [BLOCK #{block['index']}] mined  "
              f"hash={self.hash(block)[:24]}…  "
              f"records={len(block['records'])}")
        return block

    def proof_of_work(self, last_proof: int, last_hash: str) -> int:
        proof = 0
        while not self._valid_proof(last_proof, proof, last_hash):
            proof += 1
        return proof

    @staticmethod
    def _valid_proof(last_proof: int, proof: int, last_hash: str) -> bool:
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        return hashlib.sha256(guess).hexdigest()[:4] == '0000'

    # ── Chaincode: RegisterEvidence ───────────────────────────────────────────

    def add_evidence_record(self, actor: User, officer: str, badge_id: str,
                            case_id: str, case_description: str,
                            summary: str, evidence_type: str,
                            bns_section: str, offchain_meta: dict,
                            crime_scene_location: str = '',
                            lab_location: str = '') -> str:
        _require_permission(actor, ActionType.REGISTER)

        evidence_type = evidence_type.strip().lower()
        if evidence_type not in EVIDENCE_TYPES:
            raise ValueError(f"Evidence type '{evidence_type}' not in {EVIDENCE_TYPES}")
        if bns_section not in BNS_EVIDENCE_MAP:
            raise ValueError(f"Invalid BNS section: '{bns_section}'")
        allowed = BNS_EVIDENCE_MAP[bns_section]
        if evidence_type not in allowed:
            raise ValueError(
                f"Type '{evidence_type}' not allowed for '{bns_section}'. "
                f"Allowed: {allowed}"
            )

        evidence_id = f'EV-{str(uuid.uuid4())[:8].upper()}'
        record = EvidenceRecord(
            evidence_id          = evidence_id,
            officer              = officer,
            badge_id             = badge_id,
            case_id              = case_id,
            case_description     = case_description,
            summary              = summary,
            evidence_type        = evidence_type,
            bns_section          = bns_section,
            offchain_meta        = {
                'url_or_path': offchain_meta['evidence_url'],
                'filename':    offchain_meta['evidence_filename'],
                'sha256':      offchain_meta['evidence_hash'],
                'size_bytes':  offchain_meta.get('size_bytes'),
                'uploaded_at': offchain_meta.get('uploaded_at'),
            },
            registered_by        = actor,
            crime_scene_location = crime_scene_location,
            lab_location         = lab_location,
        )

        entry = ActionEntry(
            actor       = actor,
            action_type = ActionType.REGISTER,
            payload     = {
                'evidence_id':     evidence_id,
                'officer':         officer,
                'badge_id':        badge_id,
                'case_id':         case_id,
                'evidence_type':   evidence_type,
                'bns_section':     bns_section,
                'offchain_sha256': offchain_meta['evidence_hash'],
                'location':        crime_scene_location,
            },
        )
        record.append_action(entry)

        enc = aes_encrypt_json(record.to_dict())
        self.pending.append({'evidence_id': evidence_id, 'encrypted': enc})
        self.world_state[evidence_id] = record

        print(f"  [LEDGER] Evidence registered → {evidence_id}  "
              f"by {actor.name} ({actor.role.value})")
        return evidence_id

    # ── Chaincode: TransferCustody ────────────────────────────────────────────

    def transfer_custody(self, actor: User, evidence_id: str,
                         new_holder: User, reason: str = '') -> ActionEntry:
        _require_permission(actor, ActionType.TRANSFER_CUSTODY)
        record     = self._get_record(evidence_id)
        old_holder = record.current_holder
        record.current_holder = new_holder

        entry = ActionEntry(
            actor       = actor,
            action_type = ActionType.TRANSFER_CUSTODY,
            payload     = {
                'evidence_id': evidence_id,
                'from_user':   old_holder.user_id,
                'to_user':     new_holder.user_id,
                'from_name':   old_holder.name,
                'to_name':     new_holder.name,
                'reason':      reason,
            },
            prev_hash = record._last_hash(),
        )
        record.append_action(entry)
        print(f"  [LEDGER] Custody transferred → {evidence_id}: "
              f"{old_holder.name} → {new_holder.name}")
        return entry

    # ── Chaincode: IssueLabRequest ────────────────────────────────────────────

    def issue_lab_request(self, actor: User, case_id: str, context: str,
                          finding_specs: list[dict],
                          deadline: Optional[str] = None) -> LabRequest:
        _require_permission(actor, ActionType.ISSUE_LAB_REQUEST)
        for spec in finding_specs:
            self._get_record(spec['evidence_id'])

        request_id = f'LR-{str(uuid.uuid4())[:8].upper()}'
        lr = LabRequest(
            request_id = request_id,
            issued_by  = actor,
            case_id    = case_id,
            context    = context,
            deadline   = deadline,
        )

        for spec in finding_specs:
            lr.add_finding_target(
                evidence_id = spec['evidence_id'],
                description = spec['description'],
                priority    = Priority(spec.get('priority', 'MEDIUM')),
            )

        lr_entry = ActionEntry(
            actor       = actor,
            action_type = ActionType.ISSUE_LAB_REQUEST,
            payload     = {
                'request_id': request_id,
                'case_id':    case_id,
                'context':    context,
                'deadline':   lr.deadline,
                'findings':   [
                    {'finding_id': ft.finding_id,
                     'evidence_id': ft.evidence_id,
                     'description': ft.target_description,
                     'priority': ft.priority.value}
                    for ft in lr.findings
                ],
            },
        )
        lr.append_action(lr_entry)

        seen: set = set()
        for ft in lr.findings:
            eid = ft.evidence_id
            if eid in seen:
                continue
            seen.add(eid)
            ev = self.world_state[eid]
            ev.lab_request_ids.append(request_id)
            ev_entry = ActionEntry(
                actor       = actor,
                action_type = ActionType.ISSUE_LAB_REQUEST,
                payload     = {'request_id': request_id, 'evidence_id': eid,
                               'finding_ids': [f.finding_id for f in lr.findings
                                               if f.evidence_id == eid]},
                prev_hash   = ev._last_hash(),
            )
            ev.append_action(ev_entry)

        self.lab_requests[request_id] = lr
        print(f"  [LEDGER] Lab request issued → {request_id} "
              f"({len(lr.findings)} finding(s)) by {actor.name}")
        return lr

    # ── Chaincode: AcknowledgeRequest ─────────────────────────────────────────

    def acknowledge_lab_request(self, actor: User, request_id: str) -> ActionEntry:
        _require_permission(actor, ActionType.ACK_LAB_REQUEST)
        lr = self._get_lab_request(request_id)
        if lr.status != RequestStatus.ISSUED:
            raise ValueError(f"Request {request_id} is already {lr.status.value}.")

        lr.status      = RequestStatus.ACKNOWLEDGED
        lr.assigned_to = actor

        entry = ActionEntry(
            actor       = actor,
            action_type = ActionType.ACK_LAB_REQUEST,
            payload     = {'request_id': request_id, 'acknowledged_by': actor.user_id},
            prev_hash   = lr._last_hash(),
        )
        lr.append_action(entry)

        seen: set = set()
        for ft in lr.findings:
            eid = ft.evidence_id
            if eid in seen or eid not in self.world_state:
                continue
            seen.add(eid)
            ev = self.world_state[eid]
            ev.append_action(ActionEntry(
                actor       = actor,
                action_type = ActionType.ACK_LAB_REQUEST,
                payload     = {'request_id': request_id,
                               'note': f'Lab request acknowledged by {actor.name}'},
                prev_hash   = ev._last_hash(),
            ))
        print(f"  [LEDGER] Request acknowledged → {request_id} by {actor.name}")
        return entry

    # ── Chaincode: RespondToFinding ───────────────────────────────────────────

    def respond_to_finding(self, actor: User, request_id: str,
                           finding_id: str, response_text: str,
                           new_status: FindingStatus,
                           analysis_type: str = 'General Examination',
                           tool_used: str = 'N/A') -> ActionEntry:
        _require_permission(actor, ActionType.RESPOND_TO_FINDING)
        lr = self._get_lab_request(request_id)
        if lr.status not in (RequestStatus.ACKNOWLEDGED, RequestStatus.IN_PROGRESS):
            raise ValueError('Acknowledge the lab request before responding.')
        if lr.assigned_to is None or lr.assigned_to.user_id != actor.user_id:
            raise PermissionError('Only the assigned examiner can respond to this request.')
        ft = lr.get_finding(finding_id)
        if ft is None:
            raise KeyError(f"Finding '{finding_id}' not in request '{request_id}'.")
        if ft.status in (FindingStatus.RESOLVED, FindingStatus.UNABLE_TO_DETERMINE):
            raise ValueError(f"Finding {finding_id} is already closed.")

        ft.status        = new_status
        ft.lab_response  = response_text
        ft.analysis_type = analysis_type
        ft.tool_used     = tool_used
        ft.resolved_by   = actor.user_id
        ft.resolved_at   = datetime.now(timezone.utc).isoformat()

        if lr.status == RequestStatus.ACKNOWLEDGED:
            lr.status = RequestStatus.IN_PROGRESS
        lr._update_overall_status()

        lr_entry = ActionEntry(
            actor       = actor,
            action_type = ActionType.RESPOND_TO_FINDING,
            payload     = {
                'request_id':    request_id,
                'finding_id':    finding_id,
                'evidence_id':   ft.evidence_id,
                'new_status':    new_status.value,
                'response':      response_text,
                'analysis_type': analysis_type,
                'tool_used':     tool_used,
            },
            prev_hash = lr._last_hash(),
        )
        lr.append_action(lr_entry)

        if ft.evidence_id in self.world_state:
            ev = self.world_state[ft.evidence_id]
            ev.append_action(ActionEntry(
                actor       = actor,
                action_type = ActionType.LOG_ANALYSIS,
                payload     = {
                    'evidence_id':    ft.evidence_id,
                    'analysis_type':  analysis_type,
                    'findings':       response_text,
                    'tool_used':      tool_used,
                    'linked_request': request_id,
                    'linked_finding': finding_id,
                },
                prev_hash = ev._last_hash(),
            ))
        print(f"  [LEDGER] Finding responded → {finding_id}: "
              f"{new_status.value} by {actor.name}")
        return lr_entry

    # ── Chaincode: LogAnalysis (standalone) ───────────────────────────────────

    def log_analysis(self, actor: User, evidence_id: str,
                     analysis_type: str, findings: str,
                     tool_used: str = 'N/A') -> ActionEntry:
        _require_permission(actor, ActionType.LOG_ANALYSIS)
        record = self._get_record(evidence_id)
        entry  = ActionEntry(
            actor       = actor,
            action_type = ActionType.LOG_ANALYSIS,
            payload     = {'evidence_id': evidence_id, 'analysis_type': analysis_type,
                           'findings': findings, 'tool_used': tool_used},
            prev_hash   = record._last_hash(),
        )
        record.append_action(entry)
        print(f"  [LEDGER] Analysis logged → {evidence_id} by {actor.name}")
        return entry

    def preview_evidence_analysis(self, actor: User, evidence_id: str,
                                  profile: str, local_copy: str = None) -> dict:
        """Analyze registered bytes without changing evidence or closing findings."""
        _require_permission(actor, ActionType.LOG_ANALYSIS)
        record = self._get_record(evidence_id)
        if record.committed_to_chain:
            raise ValueError('Evidence is already finalized; register a new examination record.')
        return analyze_evidence(record.offchain_meta, profile, local_copy)

    def procedure_status(self, evidence_id: str) -> dict:
        """Describe actual recorded workflow; this is not a legal-compliance score."""
        record = self._get_record(evidence_id)
        requests = [self.lab_requests[rid] for rid in record.lab_request_ids]
        return {
            'evidence_registered': bool(record.history),
            'analysis_recorded': any(e.action_type == ActionType.LOG_ANALYSIS for e in record.history),
            'linked_requests_closed': all(r.status == RequestStatus.COMPLETED for r in requests),
            'linked_request_count': len(requests),
            'unresolved_findings': [f.finding_id for r in requests for f in r.findings
                                    if f.status in (FindingStatus.PENDING, FindingStatus.IN_PROGRESS)],
            'unable_to_determine_findings': [f.finding_id for r in requests for f in r.findings
                                             if f.status == FindingStatus.UNABLE_TO_DETERMINE],
            'bns_tags_present': bool(record.legal_sections['bns']),
            'snapshot_submitted': record.committed_to_chain,
            'final_snapshot_mined': any(r.get('evidence_id') == evidence_id and r.get('final_commit')
                                         for b in self.chain for r in b['records']),
        }

    # ── Phase-3: Legal Mapping & Blockchain Commit ────────────────────────────

    def map_legal_sections(self, actor: User, evidence_id: str,
                           bns: list, bnss: list,
                           bsa: list, it_act: list) -> ActionEntry:
        _require_permission(actor, ActionType.LEGAL_MAPPING)
        record = self._get_record(evidence_id)
        record.legal_sections = {'bns': bns, 'bnss': bnss, 'bsa': bsa, 'it_act': it_act}
        record.io_officer_name = actor.name
        record.io_officer_id   = actor.user_id

        entry = ActionEntry(
            actor       = actor,
            action_type = ActionType.LEGAL_MAPPING,
            payload     = {
                'evidence_id': evidence_id,
                'bns':    bns, 'bnss': bnss,
                'bsa':    bsa, 'it_act': it_act,
                'total_sections': len(bns) + len(bnss) + len(bsa) + len(it_act),
            },
            prev_hash = record._last_hash(),
        )
        record.append_action(entry)
        print(f"  [LEDGER] Legal sections mapped → {evidence_id}  "
              f"({len(bns)+len(bnss)+len(bsa)+len(it_act)} sections)")
        return entry

    def commit_evidence_to_blockchain(self, actor: User,
                                      evidence_id: str) -> ActionEntry:
        """Phase-3 final commit — generates BSA certificate and seals the record."""
        _require_permission(actor, ActionType.BLOCKCHAIN_COMMIT)
        record = self._get_record(evidence_id)
        if record.committed_to_chain:
            raise ValueError(f"Evidence {evidence_id} already committed.")

        checks = self.procedure_status(evidence_id)
        if not checks['analysis_recorded']:
            raise ValueError('Record a laboratory analysis before final submission.')
        if not checks['linked_requests_closed']:
            raise ValueError('Complete all linked laboratory finding targets before final submission.')
        if not checks['bns_tags_present']:
            raise ValueError('Add at least one illustrative BNS tag before final submission.')

        cert_id = f'BSA-CERT-{str(uuid.uuid4())[:10].upper()}'
        record.bsa_certificate_id = cert_id
        record.committed_to_chain = True
        record.committed_at       = datetime.now(timezone.utc).isoformat()

        entry = ActionEntry(
            actor       = actor,
            action_type = ActionType.BLOCKCHAIN_COMMIT,
            payload     = {
                'evidence_id':        evidence_id,
                'bsa_certificate_id': cert_id,
                'committed_at':       record.committed_at,
                'legal_sections':     record.legal_sections,
                'io_officer':         actor.name,
                'io_officer_id':      actor.user_id,
                'note': 'Final commit — evidence sealed on blockchain for court admissibility.',
            },
            prev_hash = record._last_hash(),
        )
        record.append_action(entry)
        enc = aes_encrypt_json(record.to_dict())
        self.pending.append({'evidence_id': evidence_id,
                             'encrypted': enc, 'final_commit': True})

        print(f"  [LEDGER] ✔ Evidence committed → {evidence_id}  "
              f"BSA Cert: {cert_id}")
        return entry

    # ── Chaincode: GetHistoryForKey ───────────────────────────────────────────

    def view_history(self, actor: User, evidence_id: str) -> list:
        _require_permission(actor, ActionType.VIEW_HISTORY)
        record = self._get_record(evidence_id)
        entry  = ActionEntry(
            actor       = actor,
            action_type = ActionType.VIEW_HISTORY,
            payload     = {'evidence_id': evidence_id},
            prev_hash   = record._last_hash(),
        )
        record.append_action(entry)
        return record.history

    # ── Mine block ────────────────────────────────────────────────────────────

    def mine_block(self, actor: User) -> Optional[dict]:
        _require_permission(actor, ActionType.MINE_BLOCK)
        if not self.pending:
            print('  [MINE] No pending records — nothing to mine.')
            return None
        last  = self.last_block
        proof = self.proof_of_work(last['proof'], self.hash(last))
        return self.new_block(proof)

    # ── Query helpers ─────────────────────────────────────────────────────────

    def get_lab_inbox(self, actor: User) -> list:
        _require_permission(actor, ActionType.VIEW_HISTORY)
        return [lr for lr in self.lab_requests.values()
                if lr.status not in (RequestStatus.COMPLETED, RequestStatus.WITHDRAWN)]

    def get_police_requests(self, actor: User) -> list:
        _require_permission(actor, ActionType.ISSUE_LAB_REQUEST)
        return [lr for lr in self.lab_requests.values()
                if lr.issued_by.user_id == actor.user_id]

    def verify_chain(self) -> bool:
        for i, blk in enumerate(self.chain[1:], 1):
            previous = self.chain[i - 1]
            if not self._valid_proof(previous['proof'], blk['proof'], self.hash(previous)):
                return False
            if blk['previous_hash'] != self.hash(self.chain[i - 1]):
                return False
        return True

    def _get_record(self, evidence_id: str) -> EvidenceRecord:
        if evidence_id not in self.world_state:
            raise KeyError(f"Evidence '{evidence_id}' not found in world state.")
        return self.world_state[evidence_id]

    def _get_lab_request(self, request_id: str) -> LabRequest:
        if request_id not in self.lab_requests:
            raise KeyError(f"Lab Request '{request_id}' not found.")
        return self.lab_requests[request_id]


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — REPORT GENERATOR  (BSA-style court documents)
# ══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """
    Off-chain component producing BSA-style, court-admissible reports.
    Fabric mapping: Off-chain application / REST gateway client.
    """

    def __init__(self, bc: MetadataBlockchain):
        self.bc = bc

    def _get_record(self, actor: User, evidence_id: str) -> EvidenceRecord:
        _require_permission(actor, ActionType.EXPORT_REPORT)
        return self.bc._get_record(evidence_id)

    # ── Full chain-of-custody text report (BSA-style) ─────────────────────────

    def text_report(self, actor: User, evidence_id: str) -> str:
        rec = self._get_record(actor, evidence_id)
        W   = 74
        ls  = rec.legal_sections

        lines = [
            '═' * W,
            ' DIGITAL EVIDENCE CHAIN-OF-CUSTODY REPORT'.center(W),
            ' NyayaChain Blockchain Prototype  |  Dissertation Final'.center(W),
            ' Academic demonstration — not an official statutory form'.center(W),
            '═' * W,
            f" Evidence ID         : {rec.evidence_id}",
            f" BSA Certificate     : {rec.bsa_certificate_id or 'PENDING COMMIT'}",
            f" Case ID             : {rec.case_id}",
            f" Case Description    : {rec.case_description}",
            f" Registering Officer : {rec.officer}  (Badge: {rec.badge_id})",
            f" Evidence Type       : {rec.evidence_type}",
            f" BNS Section         : {rec.bns_section}",
            f" Summary             : {rec.summary}",
            f" Crime Scene Location: {rec.crime_scene_location or 'N/A'}",
            f" Lab Location        : {rec.lab_location or 'N/A'}",
            f" Status              : {rec.status}",
            f" Committed to Chain  : {'YES ✓' if rec.committed_to_chain else 'NO — pending'}",
            f" Committed At        : {rec.committed_at or 'N/A'}",
            f" Off-chain File      : {rec.offchain_meta.get('filename', 'N/A')}",
            f" SHA-256 Hash        : {rec.offchain_meta.get('sha256', 'N/A')}",
            f" Current Holder      : {rec.current_holder.name} ({rec.current_holder.role.value})"
            f"  —  {rec.current_holder.organisation}",
            f" Lab Request IDs     : {', '.join(rec.lab_request_ids) or 'None'}",
            '─' * W,
            ' PHASE-3 LEGAL SECTION MAPPING',
            '─' * W,
            f" BNS 2023    : {', '.join(ls.get('bns', [])) or 'Not mapped'}",
            f" BNSS 2023   : {', '.join(ls.get('bnss', [])) or 'Not mapped'}",
            f" BSA 2023    : {', '.join(ls.get('bsa', [])) or 'Not mapped'}",
            f" IT Act 2000 : {', '.join(ls.get('it_act', [])) or 'Not mapped'}",
            f" IO Officer  : {rec.io_officer_name or 'N/A'}  (ID: {rec.io_officer_id or 'N/A'})",
            '─' * W,
            f" GENERATED BY : {actor.name} ({actor.role.value})  —  {actor.organisation}",
            f" GENERATED AT : {datetime.now(timezone.utc).isoformat()}",
            '═' * W,
            f" TRANSACTION HISTORY  ({len(rec.history)} entries)",
            '─' * W,
        ]

        for i, entry in enumerate(rec.history, 1):
            lines += [
                f" [{i:03d}] TX-ID      : {entry.tx_id}",
                f"       Timestamp  : {entry.timestamp}",
                f"       Actor      : {entry.actor.name} ({entry.actor.role.value})"
                f"  —  {entry.actor.organisation}",
                f"       Action     : {entry.action_type}",
                f"       Payload    : {json.dumps(entry.payload, indent=17).strip()}",
                f"       Prev Hash  : {entry.prev_hash[:32]}…",
                f"       This Hash  : {entry.entry_hash[:32]}…",
                '─' * W,
            ]

        valid = self._verify_history_chain(rec)
        lines += [
            ' RECORDED PROCEDURE STATUS (NOT A LEGAL ASSESSMENT)',
            json.dumps(self.bc.procedure_status(evidence_id), indent=2),
            ' INTEGRITY VERIFICATION',
            '─' * W,
            f" History chain intact : {'✓ VERIFIED' if valid else '✗ TAMPERING DETECTED'}",
            f" Block chain valid    : {'✓ VALID'    if self.bc.verify_chain() else '✗ INVALID'}",
            f" Total transactions   : {len(rec.history)}",
            '═' * W,
        ]
        return '\n'.join(lines)

    # ── BSA Certificate of Authenticity ──────────────────────────────────────

    def bsa_certificate(self, actor: User, evidence_id: str) -> str:
        rec = self._get_record(actor, evidence_id)
        W   = 74
        lines = [
            '═' * W,
            ' DEMONSTRATION CERTIFICATE — NOT A LEGAL CERTIFICATE'.center(W),
            ' Academic report template; legal content requires review'.center(W),
            ' Under Bharatiya Sakshya Adhiniyam 2023 — Sec. 63'.center(W),
            '═' * W,
            f" Certificate ID  : {rec.bsa_certificate_id or 'NOT YET COMMITTED'}",
            f" Case ID         : {rec.case_id}",
            f" Evidence ID     : {rec.evidence_id}",
            f" Evidence Type   : {rec.evidence_type}",
            f" BNS Section     : {rec.bns_section}",
            '─' * W,
            ' PART A — ORIGIN OFFICER DECLARATION',
            '─' * W,
            f" Officer Name    : {rec.officer}",
            f" Badge / ID      : {rec.badge_id}",
            f" Organisation    : {rec.current_holder.organisation}",
            f" Crime Scene     : {rec.crime_scene_location or 'N/A'}",
            f" Evidence SHA-256: {rec.offchain_meta.get('sha256', 'N/A')}",
            '─' * W,
            ' PART B — INVESTIGATING OFFICER / LAB CERTIFICATION',
            '─' * W,
            f" IO Officer      : {rec.io_officer_name or 'N/A'}",
            f" IO Officer ID   : {rec.io_officer_id or 'N/A'}",
            f" Lab Location    : {rec.lab_location or 'N/A'}",
            f" Committed At    : {rec.committed_at or 'Not yet committed'}",
            '─' * W,
            ' BLOCKCHAIN INTEGRITY',
            '─' * W,
            f" Block Hash      : {self.bc.hash(self.bc.last_block)[:48]}…",
            f" Latest TX Hash  : {rec.history[-1].entry_hash[:48] if rec.history else 'N/A'}…",
            f" Chain Valid     : {'✓ YES' if self.bc.verify_chain() else '✗ INVALID'}",
            f" History Intact  : {'✓ YES' if self._verify_history_chain(rec) else '✗ INVALID'}",
            '─' * W,
            f" Generated By    : {actor.name} ({actor.role.value})",
            f" Generated At    : {datetime.now(timezone.utc).isoformat()}",
            '═' * W,
        ]
        return '\n'.join(lines)

    # ── Lab request findings brief ─────────────────────────────────────────────

    def lab_request_report(self, actor: User, request_id: str) -> str:
        _require_permission(actor, ActionType.EXPORT_REPORT)
        lr = self.bc._get_lab_request(request_id)
        W  = 74
        status_icons = {
            FindingStatus.PENDING:             '○ PENDING',
            FindingStatus.IN_PROGRESS:         '◑ IN PROGRESS',
            FindingStatus.RESOLVED:            '✓ RESOLVED',
            FindingStatus.UNABLE_TO_DETERMINE: '✗ UNABLE TO DETERMINE',
        }
        lines = [
            '═' * W,
            ' FORENSIC LAB REQUEST — FINDINGS BRIEF'.center(W),
            ' NyayaChain Blockchain Prototype'.center(W),
            '═' * W,
            f" Request ID    : {lr.request_id}",
            f" Case ID       : {lr.case_id}",
            f" Issued By     : {lr.issued_by.name} ({lr.issued_by.role.value})"
            f"  —  {lr.issued_by.organisation}",
            f" Assigned To   : {lr.assigned_to.name if lr.assigned_to else 'Not yet assigned'}",
            f" Status        : {lr.status.value}",
            f" Deadline      : {lr.deadline}",
            f" Created At    : {lr.created_at}",
            f" Report By     : {actor.name} ({actor.role.value})",
            f" Generated At  : {datetime.now(timezone.utc).isoformat()}",
            '─' * W,
            ' CASE CONTEXT / INSTRUCTIONS TO LAB',
            '─' * W,
            f" {lr.context}",
            '═' * W,
            f" FINDING TARGETS  ({len(lr.findings)} items)",
            '─' * W,
        ]
        for i, ft in enumerate(lr.findings, 1):
            lines += [
                f" [{i:02d}] Finding ID   : {ft.finding_id}",
                f"      Evidence     : {ft.evidence_id}",
                f"      Priority     : {ft.priority.value}",
                f"      Status       : {status_icons.get(ft.status, ft.status.value)}",
                f"      Target       : {ft.target_description}",
            ]
            if ft.lab_response:
                lines += [
                    f"      Lab Response : {ft.lab_response}",
                    f"      Analysis     : {ft.analysis_type}",
                    f"      Tool Used    : {ft.tool_used}",
                    f"      Resolved By  : {ft.resolved_by}  at  {ft.resolved_at}",
                ]
            lines.append('─' * W)

        lines += [' REQUEST TRANSACTION HISTORY', '─' * W]
        for i, entry in enumerate(lr.history, 1):
            lines.append(
                f" [{i:03d}] {entry.timestamp}  "
                f"{entry.action_type:<28}  by {entry.actor.name}"
            )
        lines.append('═' * W)
        return '\n'.join(lines)

    # ── JSON report ───────────────────────────────────────────────────────────

    def json_report(self, actor: User, evidence_id: str) -> str:
        rec    = self._get_record(actor, evidence_id)
        linked = {req_id: self.bc.lab_requests[req_id].to_dict()
                  for req_id in rec.lab_request_ids
                  if req_id in self.bc.lab_requests}
        report = {
            'report_metadata': {
                'report_id':          str(uuid.uuid4()),
                'generated_at':       datetime.now(timezone.utc).isoformat(),
                'generated_by': {
                    'user_id':      actor.user_id,
                    'name':         actor.name,
                    'role':         actor.role.value,
                    'organisation': actor.organisation,
                },
                'prototype_version':  'NyayaChain-Dissertation-Final',
                'blockchain_mapping': 'Hyperledger Fabric (simulated)',
                'bns_reference':      'Bharatiya Nyaya Sanhita 2023',
                'bsa_reference':      'Bharatiya Sakshya Adhiniyam 2023',
                'bnss_reference':     'Bharatiya Nagarik Suraksha Sanhita 2023',
            },
            'evidence':            rec.to_dict(),
            'linked_lab_requests': linked,
            'procedure_status': self.bc.procedure_status(evidence_id),
            'integrity': {
                'history_chain_valid': self._verify_history_chain(rec),
                'block_chain_valid':   self.bc.verify_chain(),
                'total_transactions':  len(rec.history),
                'genesis_tx_hash':     rec.history[0].entry_hash if rec.history else 'N/A',
                'latest_tx_hash':      rec.history[-1].entry_hash if rec.history else 'N/A',
            },
        }
        return json.dumps(report, indent=2)

    # ── Chain integrity verification ──────────────────────────────────────────

    def _verify_history_chain(self, rec: EvidenceRecord) -> bool:
        for i, entry in enumerate(rec.history):
            recomp           = ActionEntry(entry.actor, entry.action_type,
                                           entry.payload, entry.prev_hash)
            recomp.tx_id     = entry.tx_id
            recomp.timestamp = entry.timestamp
            recomp.entry_hash = recomp._compute_hash()
            if recomp.entry_hash != entry.entry_hash:
                return False
            if i > 0 and entry.prev_hash != rec.history[i - 1].entry_hash:
                return False
        return True


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 14 — ANSI COLOUR HELPERS
# ══════════════════════════════════════════════════════════════════════════════

RST = '\033[0m';  BLD = '\033[1m'
RED = '\033[91m'; GRN = '\033[92m'; YLW = '\033[93m'
CYN = '\033[96m'; BLU = '\033[94m'; MGN = '\033[95m'
WHT = '\033[97m'

# Disable colours on Windows if ANSI not supported
if sys.platform == 'win32':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        RST = BLD = RED = GRN = YLW = CYN = BLU = MGN = WHT = ''


def cc(col, txt):  return f"{col}{txt}{RST}"
def hdr(title):
    W = 68
    print(cc(CYN, '╔' + '═' * W + '╗'))
    print(cc(CYN, '║') + cc(BLD + WHT, title.center(W)) + cc(CYN, '║'))
    print(cc(CYN, '╚' + '═' * W + '╝'))

def ok(m):   print(cc(GRN, f"  ✔  {m}"))
def warn(m): print(cc(YLW, f"  ⚠  {m}"))
def err(m):  print(cc(RED, f"  ✘  {m}"))
def ask(m):  return input(cc(MGN, f"  ➤ {m}: ")).strip()
def rule(w=70): print(cc(CYN, '─' * w))
def pause(): input(cc(CYN, '\n  Press Enter to continue…'))

STATUS_COL = {
    'ISSUED': YLW, 'ACKNOWLEDGED': CYN, 'IN_PROGRESS': BLU,
    'COMPLETED': GRN, 'WITHDRAWN': RED, 'ACTIVE': GRN,
    'PENDING': YLW, 'RESOLVED': GRN, 'UNABLE_TO_DETERMINE': RED,
}


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 15 — SEED USERS
# ══════════════════════════════════════════════════════════════════════════════

SEED_USERS = {
    'P001': User('P001', 'SI Alice Carter',   Role.POLICE,       'Metropolitan Police',    'BADGE-P001'),
    'P002': User('P002', 'DSP Ben Malik',      Role.POLICE,       'Metropolitan Police',    'BADGE-P002'),
    'L001': User('L001', 'Dr. Sara Okafor',    Role.FORENSIC_LAB, 'National Forensic Lab',  'BADGE-L001'),
    'L002': User('L002', 'Tech James Liu',     Role.FORENSIC_LAB, 'National Forensic Lab',  'BADGE-L002'),
    'C001': User('C001', 'Judge P. Wong',      Role.COURT_VIEWER, 'Crown Court',            'BADGE-C001'),
    'C002': User('C002', 'Adv. R. Singh',      Role.COURT_VIEWER, 'Crown Court',            'BADGE-C002'),
}

ROLE_COL = {Role.POLICE: BLU, Role.FORENSIC_LAB: YLW, Role.COURT_VIEWER: GRN}


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 16 — SHARED UI HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def login(bc: MetadataBlockchain) -> User:
    os.system('cls' if os.name == 'nt' else 'clear')
    hdr('  NyayaChain — Blockchain Forensic Evidence Platform')
    print(cc(BLU, '\n  Enrolled Identities:'))
    rule()
    for uid, u in SEED_USERS.items():
        rc = ROLE_COL.get(u.role, RST)
        print(f"  {cc(BLD, uid)}  {cc(rc, u.name):<42} "
              f"[{u.role.value}]  {u.organisation}")
    rule()
    print(cc(YLW, "\n  Demo passwords:"))
    for role, key in DEMO_KEYS.items():
        print(f"    {role:<16} →  {key}")
    print()
    while True:
        uid = ask('User ID (e.g. P001)').upper()
        if uid in SEED_USERS:
            user     = SEED_USERS[uid]
            role_key = DEMO_KEYS.get(user.role.value, '')
            key_in   = ask(f'Password for [{user.role.value}]')
            if key_in != role_key:
                err('Incorrect password.'); continue
            rc = ROLE_COL.get(user.role, RST)
            print()
            ok(f"Logged in as {cc(rc, user.name)}  |  role: {user.role.value}"
               f"  |  org: {user.organisation}")
            pause()
            return user
        err('User ID not found. Try again.')


def list_evidence(bc: MetadataBlockchain):
    if not bc.world_state:
        warn('No evidence in the ledger yet.'); return
    print(cc(BLD, '\n  Evidence in World State:'))
    rule()
    for eid, rec in bc.world_state.items():
        committed  = cc(GRN, ' [COMMITTED]') if rec.committed_to_chain else ''
        lr_flag    = cc(YLW, f' [{len(rec.lab_request_ids)} req]') \
                     if rec.lab_request_ids else ''
        sc         = STATUS_COL.get(rec.status, RST)
        print(f"  {cc(CYN, eid)}  {rec.case_id:<14}  "
              f"{rec.evidence_type:<14}  "
              f"{cc(sc, rec.status):<8}  "
              f"{rec.summary[:34]}{committed}{lr_flag}")
    rule()


def pick_evidence(bc: MetadataBlockchain) -> Optional[str]:
    list_evidence(bc)
    if not bc.world_state:
        return None
    eid = ask('Evidence ID (blank to cancel)').upper()
    if not eid:
        return None
    if eid not in bc.world_state:
        err('Evidence ID not found.'); return None
    return eid


def pick_lab_request(bc: MetadataBlockchain,
                     pool=None) -> Optional[LabRequest]:
    pool = pool if pool is not None else list(bc.lab_requests.values())
    if not pool:
        warn('No lab requests found.'); return None
    print(cc(BLD, '\n  Lab Requests:'))
    rule()
    for lr in pool:
        sc      = STATUS_COL.get(lr.status.value, RST)
        pending = sum(1 for ft in lr.findings if ft.status == FindingStatus.PENDING)
        print(f"  {cc(CYN, lr.request_id)}  {lr.case_id:<14}  "
              f"Status: {cc(sc, lr.status.value):<14}  "
              f"{len(lr.findings)} finding(s)  |  {pending} pending")
    rule()
    rid = ask('Request ID (blank to cancel)').upper()
    if not rid or rid not in bc.lab_requests:
        return None
    return bc.lab_requests[rid]


def pick_user(exclude: User = None) -> Optional[User]:
    print(cc(BLD, '\n  Select recipient:'))
    rule()
    for uid, u in SEED_USERS.items():
        if exclude and uid == exclude.user_id:
            continue
        rc = ROLE_COL.get(u.role, RST)
        print(f"  {uid}  {cc(rc, u.name):<42} [{u.role.value}]")
    rule()
    uid = ask('User ID').upper()
    return SEED_USERS.get(uid)


def get_offchain_meta() -> Optional[dict]:
    print(cc(YLW, '  Off-chain evidence: URL (http/https) or local file/dir path.'))
    loc = ask('Evidence URL / local path  (blank = demo stub)')
    if not loc:
        meta = _stub_offchain_meta()
        ok(f"Demo stub  sha256={meta['evidence_hash'][:24]}…")
        return meta
    try:
        meta = ingest_offchain_evidence(loc)
        ok(f"Ingested: {meta['evidence_filename']}  "
           f"sha256={meta['evidence_hash'][:24]}…")
        return meta
    except Exception as e:
        err(f'Ingest failed: {e}'); return None


def show_lab_inbox_banner(user: User, bc: MetadataBlockchain):
    inbox = bc.get_lab_inbox(user)
    if not inbox: return
    print(cc(YLW, f"\n  ┌{'─'*62}┐"))
    print(cc(YLW,  f"  │{'  📥  FORENSIC LAB INBOX'.center(62)}│"))
    print(cc(YLW,  f"  ├{'─'*62}┤"))
    for lr in inbox:
        sc      = STATUS_COL.get(lr.status.value, RST)
        pending = sum(1 for ft in lr.findings if ft.status == FindingStatus.PENDING)
        line    = f"  {lr.request_id}  {lr.case_id}  {lr.status.value}  {pending} pending"
        print(cc(YLW, '  │') + f' {cc(sc, line):<72}' + cc(YLW, '│'))
    print(cc(YLW,  f"  └{'─'*62}┘\n"))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 17 — POLICE MENU
# ══════════════════════════════════════════════════════════════════════════════

def menu_police(user: User, bc: MetadataBlockchain, reporter: ReportGenerator):
    OPTS = {
        '1': 'Register new evidence',
        '2': 'Transfer custody to lab / another officer',
        '3': 'Mine pending block',
        '4': 'View evidence history',
        '5': cc(YLW + BLD, 'Issue lab request  (findings brief)'),
        '6': 'View my outgoing lab requests',
        '7': cc(GRN + BLD, 'Phase-3: Map legal sections & commit to blockchain'),
        '8': 'Export text report (chain-of-custody)',
        '9': 'Export BSA Certificate of Authenticity',
        'J': 'Export JSON report',
        'S': 'Blockchain summary',
        '0': 'Logout',
    }
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        hdr(f'  POLICE MENU  ─  {user.name}  [{user.badge_id}]')
        rule()
        for k, v in OPTS.items():
            print(f"  {cc(BLU, k)}.  {v}")
        rule()
        ch = ask('Select').upper()

        if ch == '1':
            _police_register_evidence(user, bc)

        elif ch == '2':
            eid = pick_evidence(bc)
            if eid:
                new_holder = pick_user(exclude=user)
                if new_holder:
                    reason = ask('Reason for transfer')
                    try:
                        bc.transfer_custody(user, eid, new_holder, reason)
                        ok('Custody transferred.')
                    except Exception as e:
                        err(str(e))

        elif ch == '3':
            try:
                blk = bc.mine_block(user)
                if blk:
                    ok(f"Block #{blk['index']} mined. "
                       f"Hash: {MetadataBlockchain.hash(blk)[:32]}…")
            except Exception as e:
                err(str(e))

        elif ch == '4':
            _show_history(user, bc)

        elif ch == '5':
            _police_issue_lab_request(user, bc)

        elif ch == '6':
            _police_view_requests(user, bc, reporter)

        elif ch == '7':
            _police_phase3_legal_mapping(user, bc)

        elif ch == '8':
            eid = pick_evidence(bc)
            if eid:
                print(reporter.text_report(user, eid))

        elif ch == '9':
            eid = pick_evidence(bc)
            if eid:
                print(reporter.bsa_certificate(user, eid))

        elif ch == 'J':
            eid = pick_evidence(bc)
            if eid:
                j     = reporter.json_report(user, eid)
                fname = f'report_{eid}.json'
                with open(fname, 'w') as f: f.write(j)
                ok(f'JSON report saved → {fname}')
                print(j[:800] + '\n  …[truncated — see file]…' if len(j) > 800 else j)

        elif ch == 'S':
            print(cc(BLD, '\n  Blockchain summary:'))
            for blk in bc.chain:
                print(f"  Block #{blk['index']}  "
                      f"records={len(blk['records'])}  "
                      f"hash={MetadataBlockchain.hash(blk)[:32]}…")
            ok(f"Chain integrity: {'valid ✓' if bc.verify_chain() else 'INVALID ✗'}")

        elif ch == '0':
            break
        else:
            warn('Invalid option.')

        if ch != '0':
            pause()


def _police_register_evidence(user: User, bc: MetadataBlockchain):
    os.system('cls' if os.name == 'nt' else 'clear')
    hdr('  REGISTER EVIDENCE  —  Phase 1')
    officer  = ask(f'Registering officer name  [{user.name}]') or user.name
    badge_id = ask(f'Badge / ID  [{user.badge_id}]') or user.badge_id
    case_id  = ask('Case ID')
    case_desc = ask('Brief case description')
    summary  = ask('Short evidence summary')
    loc      = ask('Crime scene / seizure location')

    print(cc(BLD, '\n  Available BNS Sections:'))
    rule()
    for i, s in enumerate(BNS_SECTIONS, 1):
        print(f"  {cc(CYN, str(i)):>5}.  {s}")
        print(f"           Allowed types: {BNS_EVIDENCE_MAP[s]}")
    rule()
    sec = ask('Enter exact BNS section name')
    if sec not in BNS_EVIDENCE_MAP:
        err('Invalid BNS section.'); return
    print(f"  Allowed evidence types: {cc(GRN, str(BNS_EVIDENCE_MAP[sec]))}")
    etype = ask('Evidence type').strip().lower()

    meta = get_offchain_meta()
    if not meta: return

    lab_loc = ask('Forensic lab location (if applicable, else blank)')

    try:
        eid = bc.add_evidence_record(
            actor                = user,
            officer              = officer,
            badge_id             = badge_id,
            case_id              = case_id,
            case_description     = case_desc,
            summary              = summary,
            evidence_type        = etype,
            bns_section          = sec,
            offchain_meta        = meta,
            crime_scene_location = loc,
            lab_location         = lab_loc,
        )
        ok(f'Evidence registered: {cc(CYN, eid)}')
        ok(f'SHA-256: {meta["evidence_hash"]}')
    except Exception as e:
        err(str(e))


def _police_issue_lab_request(user: User, bc: MetadataBlockchain):
    if not bc.world_state:
        warn('No evidence registered yet.'); return

    os.system('cls' if os.name == 'nt' else 'clear')
    hdr('  ISSUE LAB REQUEST  —  Findings Brief')

    case_id  = ask('Case ID this request covers')
    context  = ask('Case context / background instructions to the lab')
    deadline = ask('Deadline (e.g. 2025-06-01, or blank)')

    finding_specs: list = []
    print(cc(BLD, "\n  Add finding targets — what you want the lab to examine."))
    print(cc(CYN,  "  Type 'done' as Evidence ID when finished.\n"))

    while True:
        list_evidence(bc)
        eid = ask("Evidence ID for this finding  (or 'done')").upper()
        if eid == 'DONE': break
        if eid not in bc.world_state:
            err('Evidence ID not found.'); continue
        desc = ask('What should the lab look for / examine?')
        print('  Priority: 1=LOW  2=MEDIUM  3=HIGH  4=CRITICAL')
        p    = ask('Priority [default=MEDIUM]')
        prio = {'1': 'LOW', '2': 'MEDIUM', '3': 'HIGH', '4': 'CRITICAL'}.get(p, 'MEDIUM')
        finding_specs.append({'evidence_id': eid, 'description': desc, 'priority': prio})
        ok(f'Finding target added: {eid} [{prio}]')
        if ask('Add another? (y/n)').lower() != 'y': break

    if not finding_specs:
        warn('No finding targets — request cancelled.'); return

    print(cc(BLD, '\n  ── Request Preview ──────────────────────'))
    print(f"  Case ID   : {case_id}")
    print(f"  Context   : {context}")
    print(f"  Deadline  : {deadline or 'Not specified'}")
    for i, fs in enumerate(finding_specs, 1):
        print(f"    [{i}] {fs['evidence_id']}  [{fs['priority']}]  {fs['description']}")

    if ask('\n  Issue this request? (y/n)').lower() != 'y':
        warn('Cancelled.'); return

    try:
        lr = bc.issue_lab_request(
            actor         = user,
            case_id       = case_id,
            context       = context,
            finding_specs = finding_specs,
            deadline      = deadline or None,
        )
        ok(f'Lab request issued: {cc(CYN, lr.request_id)}')
        ok(f'{len(lr.findings)} finding target(s) recorded on-chain.')
        warn('Tip: Also transfer custody of evidence items to a lab user.')
    except Exception as e:
        err(str(e))


def _police_view_requests(user: User, bc: MetadataBlockchain,
                          reporter: ReportGenerator):
    my_reqs = bc.get_police_requests(user)
    if not my_reqs:
        warn('No lab requests issued yet.'); return
    lr = pick_lab_request(bc, my_reqs)
    if not lr: return
    sub = ask('1=Summary  2=Full text report  (blank=back)')
    if sub == '1':
        print(cc(BLD, f'\n  Request: {lr.request_id}  —  {lr.case_id}'))
        print(f"  Status   : {cc(STATUS_COL.get(lr.status.value, RST), lr.status.value)}")
        print(f"  Deadline : {lr.deadline}")
        rule()
        for ft in lr.findings:
            sc = STATUS_COL.get(ft.status.value, RST)
            print(f"  {cc(CYN, ft.finding_id)}  [{ft.priority.value}]  "
                  f"EV={ft.evidence_id}  {cc(sc, ft.status.value)}")
            print(f"      Target: {ft.target_description}")
            if ft.lab_response:
                print(f"      Response: {ft.lab_response}")
    elif sub == '2':
        print(reporter.lab_request_report(user, lr.request_id))


def _police_phase3_legal_mapping(user: User, bc: MetadataBlockchain):
    """Phase-3: Investigating Officer maps legal sections and commits to blockchain."""
    os.system('cls' if os.name == 'nt' else 'clear')
    hdr('  PHASE 3 — INVESTIGATING OFFICER FINAL REVIEW')
    print(cc(YLW, '  Map applicable legal sections and commit evidence to blockchain.\n'))

    eid = pick_evidence(bc)
    if not eid: return
    rec = bc.world_state[eid]

    if rec.committed_to_chain:
        warn(f'Evidence {eid} is already committed to the blockchain.')
        warn(f'BSA Certificate: {rec.bsa_certificate_id}'); return

    # ── BNS sections ──────────────────────────────────────────────────────────
    print(cc(BLD, '\n  BNS 2023 Applicable Sections:'))
    rule()
    for i, s in enumerate(BNS_CYBER_LAWS, 1):
        print(f"  {cc(CYN, str(i)):>5}.  {cc(BLD, s['code']):<22}  {s['title']}")
        print(f"           {s['note']}")
        if s.get('punishment'):
            print(f"           {cc(YLW, 'Punishment: ' + s['punishment'])}")
    rule()
    bns_input = ask('Enter BNS section code(s) separated by comma (e.g. Sec. 111(1),Sec. 77)')
    bns_sel   = [x.strip() for x in bns_input.split(',') if x.strip()]

    # ── BNSS sections ─────────────────────────────────────────────────────────
    print(cc(BLD, '\n  BNSS 2023 Procedural Sections:'))
    rule()
    for i, s in enumerate(BNSS_SECTIONS_LIST, 1):
        print(f"  {cc(BLU, str(i)):>5}.  {cc(BLD, s['code']):<26}  {s['title']}")
        print(f"           {s['note']}")
    rule()
    bnss_input = ask('Enter BNSS code(s) separated by comma (blank to skip)')
    bnss_sel   = [x.strip() for x in bnss_input.split(',') if x.strip()]

    # ── BSA sections ──────────────────────────────────────────────────────────
    print(cc(BLD, '\n  BSA 2023 Digital Evidence Sections:'))
    rule()
    for i, s in enumerate(BSA_SECTIONS_LIST, 1):
        print(f"  {cc(MGN, str(i)):>5}.  {cc(BLD, s['code']):<20}  {s['title']}")
        print(f"           {s['note']}")
    rule()
    bsa_input = ask('Enter BSA code(s) separated by comma (blank to skip)')
    bsa_sel   = [x.strip() for x in bsa_input.split(',') if x.strip()]

    # ── IT Act sections ───────────────────────────────────────────────────────
    print(cc(BLD, '\n  IT Act 2000 Cyber Crime Sections:'))
    rule()
    for i, s in enumerate(IT_ACT_LIST, 1):
        print(f"  {cc(YLW, str(i)):>5}.  {cc(BLD, s['code']):<24}  {s['title']}")
        print(f"           {s['note']}")
    rule()
    it_input = ask('Enter IT Act code(s) separated by comma (blank to skip)')
    it_sel   = [x.strip() for x in it_input.split(',') if x.strip()]

    total = len(bns_sel) + len(bnss_sel) + len(bsa_sel) + len(it_sel)
    if total == 0:
        warn('No legal sections selected — at least one BNS section is required.')
        if ask('Proceed anyway? (y/n)').lower() != 'y': return

    # ── Preview ───────────────────────────────────────────────────────────────
    print(cc(BLD, '\n  ── Legal Mapping Summary ─────────────────────────'))
    print(f"  Evidence    : {eid}")
    print(f"  BNS 2023    : {', '.join(bns_sel) or 'None'}")
    print(f"  BNSS 2023   : {', '.join(bnss_sel) or 'None'}")
    print(f"  BSA 2023    : {', '.join(bsa_sel) or 'None'}")
    print(f"  IT Act 2000 : {', '.join(it_sel) or 'None'}")
    print(f"  Total       : {total} section(s)")

    if ask('\n  Map and commit to blockchain? (y/n)').lower() != 'y':
        warn('Cancelled.'); return

    try:
        bc.map_legal_sections(user, eid,
                              bns=bns_sel, bnss=bnss_sel,
                              bsa=bsa_sel, it_act=it_sel)
        entry = bc.commit_evidence_to_blockchain(user, eid)
        ok(f'Legal sections mapped. TX: {entry.tx_id[:24]}…')
        ok(f'Evidence {cc(CYN, eid)} committed to blockchain.')
        ok(f'BSA Certificate ID: {cc(GRN, rec.bsa_certificate_id)}')
        warn('Remember to mine a block to include the commit record.')
    except Exception as e:
        err(str(e))


def _show_history(user: User, bc: MetadataBlockchain):
    eid = pick_evidence(bc)
    if not eid: return
    history = bc.view_history(user, eid)
    print(cc(BLD, f'\n  Transaction History — {eid}  ({len(history)} entries)'))
    rule()
    for entry in history:
        ac = STATUS_COL.get(entry.action_type.value, RST)
        print(f"  {cc(CYN, entry.tx_id[:12])}…  "
              f"{entry.timestamp}  "
              f"{cc(ac, entry.action_type.value):<26}  "
              f"by {entry.actor.name}")
    rule()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 18 — FORENSIC LAB MENU
# ══════════════════════════════════════════════════════════════════════════════

def menu_lab(user: User, bc: MetadataBlockchain, reporter: ReportGenerator):
    OPTS = {
        '1': 'View evidence list',
        '2': cc(YLW + BLD, 'View & acknowledge lab request inbox'),
        '3': cc(YLW + BLD, 'Respond to a finding target'),
        '4': 'Log standalone analysis action',
        '5': 'Transfer custody (return evidence)',
        '6': 'View evidence history',
        '7': 'Export evidence text report',
        '8': 'Export evidence JSON report',
        '9': 'Export lab request findings brief',
        'A': 'Analyze registered evidence data (supported exports)',
        '0': 'Logout',
    }
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        hdr(f'  FORENSIC LAB MENU  ─  {user.name}  [{user.badge_id}]')
        show_lab_inbox_banner(user, bc)
        for k, v in OPTS.items():
            print(f"  {cc(YLW, k)}.  {v}")
        rule()
        ch = ask('Select').upper()

        if ch == '1':
            list_evidence(bc)

        elif ch == '2':
            _lab_view_inbox(user, bc)

        elif ch == '3':
            _lab_respond_to_finding(user, bc)

        elif ch == '4':
            eid = pick_evidence(bc)
            if eid:
                atype   = ask('Analysis type')
                finding = ask('Findings / notes')
                tool    = ask('Tool / instrument used')
                try:
                    bc.log_analysis(user, eid, atype, finding, tool)
                    ok('Analysis logged.')
                except Exception as e:
                    err(str(e))

        elif ch == '5':
            eid = pick_evidence(bc)
            if eid:
                new_holder = pick_user(exclude=user)
                if new_holder:
                    reason = ask('Reason for transfer')
                    try:
                        bc.transfer_custody(user, eid, new_holder, reason)
                        ok('Custody transferred.')
                    except Exception as e:
                        err(str(e))

        elif ch == '6':
            _show_history(user, bc)

        elif ch == '7':
            eid = pick_evidence(bc)
            if eid: print(reporter.text_report(user, eid))

        elif ch == '8':
            eid = pick_evidence(bc)
            if eid:
                j     = reporter.json_report(user, eid)
                fname = f'report_{eid}.json'
                with open(fname, 'w') as f: f.write(j)
                ok(f'Saved → {fname}')
                print(j[:800] + '\n  …[truncated — see file]…' if len(j) > 800 else j)

        elif ch == '9':
            lr = pick_lab_request(bc)
            if lr: print(reporter.lab_request_report(user, lr.request_id))

        elif ch == 'A':
            eid = pick_evidence(bc)
            if eid:
                result = _preview_analysis_ui(user, bc, eid)
                if result and ask('Record these observations in evidence history? (y/n)').lower() == 'y':
                    try:
                        bc.log_analysis(user, eid, 'Data-derived ' + result['profile'],
                                        format_analysis(result), result['engine'])
                        ok('Observations recorded. Unsupported items remain marked for manual examination.')
                    except Exception as e:
                        err(str(e))

        elif ch == '0':
            break
        else:
            warn('Invalid option.')

        if ch != '0':
            pause()


def _lab_view_inbox(user: User, bc: MetadataBlockchain):
    inbox = bc.get_lab_inbox(user)
    if not inbox:
        warn('Inbox is empty.'); return
    lr = pick_lab_request(bc, inbox)
    if not lr: return

    print(cc(BLD, f'\n  ── Request: {lr.request_id}  ({lr.case_id}) ──'))
    print(f"  Issued by  : {lr.issued_by.name} — {lr.issued_by.organisation}")
    print(f"  Status     : {cc(STATUS_COL.get(lr.status.value, RST), lr.status.value)}")
    print(f"  Deadline   : {lr.deadline}")
    print(f"  Context    : {lr.context}")
    rule()
    print(cc(BLD, '  Finding Targets:'))
    for ft in lr.findings:
        sc = STATUS_COL.get(ft.status.value, RST)
        print(f"  {cc(CYN, ft.finding_id)}  EV={ft.evidence_id}  "
              f"[{ft.priority.value}]  {cc(sc, ft.status.value)}")
        print(f"    → {ft.target_description}")

    if lr.status == RequestStatus.ISSUED:
        if ask('\n  Acknowledge receipt of this request? (y/n)').lower() == 'y':
            try:
                bc.acknowledge_lab_request(user, lr.request_id)
                ok(f'Request {lr.request_id} acknowledged.')
            except Exception as e:
                err(str(e))


def _preview_analysis_ui(user: User, bc: MetadataBlockchain, evidence_id: str):
    print('  Profiles: email, authentication, identity, network, inventory')
    profile = ask('Profile relevant to your evidence / finding').lower()
    local_copy = ask('Optional local evidence copy (blank uses registered location)') or None
    try:
        result = bc.preview_evidence_analysis(user, evidence_id, profile, local_copy)
        print(format_analysis(result))
        return result
    except Exception as e:
        err(str(e)); return None


def _lab_respond_to_finding(user: User, bc: MetadataBlockchain):
    inbox  = bc.get_lab_inbox(user)
    active = [lr for lr in inbox
              if lr.status.value in ('ACKNOWLEDGED', 'IN_PROGRESS')]
    if not active:
        warn('No acknowledged / in-progress requests.\n'
             '  Acknowledge a request first (option 2).'); return

    lr = pick_lab_request(bc, active)
    if not lr: return

    open_ft = [ft for ft in lr.findings
               if ft.status.value in ('PENDING', 'IN_PROGRESS')]
    if not open_ft:
        warn('All findings in this request are already closed.'); return

    print(cc(BLD, f'\n  Open Findings in {lr.request_id}:'))
    rule()
    for ft in open_ft:
        sc = STATUS_COL.get(ft.status.value, RST)
        print(f"  {cc(CYN, ft.finding_id)}  [{ft.priority.value}]  "
              f"EV={ft.evidence_id}  {cc(sc, ft.status.value)}")
        print(f"    → {ft.target_description}")

    fid = ask('\n  Finding ID to respond to').upper()
    ft  = lr.get_finding(fid)
    if ft is None or ft.status.value not in ('PENDING', 'IN_PROGRESS'):
        err('Invalid or already-closed Finding ID.'); return

    print(cc(BLD, f'\n  Responding to {fid}: {ft.target_description}'))
    mode = ask('Analysis mode: 1=derive observations from evidence, 2=manual examiner findings')
    if mode == '1':
        result = _preview_analysis_ui(user, bc, ft.evidence_id)
        if result is None:
            return
        if result['status'] == 'MANUAL_EXAMINATION_REQUIRED':
            warn('No applicable observations could be extracted. This target cannot be automatically resolved.')
            return
        atype = 'Data-derived ' + result['profile']
        response = format_analysis(result)
        tool = result['engine']
        warn('Review whether these observations answer this specific target before selecting an outcome.')
    elif mode == '2':
        atype    = ask('Analysis type performed')
        response = ask('Findings / response to the police brief')
        tool     = ask('Tool / instrument used')
    else:
        err('Invalid analysis mode.'); return
    print('  Outcome: 1=RESOLVED  2=IN_PROGRESS  3=UNABLE_TO_DETERMINE')
    omap = {'1': FindingStatus.RESOLVED,
            '2': FindingStatus.IN_PROGRESS,
            '3': FindingStatus.UNABLE_TO_DETERMINE}
    outcome = omap.get(ask('Outcome'))
    if not outcome:
        err('Invalid outcome.'); return

    try:
        bc.respond_to_finding(
            actor         = user,
            request_id    = lr.request_id,
            finding_id    = fid,
            response_text = response,
            new_status    = outcome,
            analysis_type = atype,
            tool_used     = tool,
        )
        ok(f'Response recorded for {fid}. Request status: {lr.status.value}')
        if lr.status == RequestStatus.COMPLETED:
            ok(f'All findings closed — request {lr.request_id} COMPLETED (review individual outcomes).')
    except Exception as e:
        err(str(e))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 19 — COURT VIEWER MENU
# ══════════════════════════════════════════════════════════════════════════════

def menu_court(user: User, bc: MetadataBlockchain, reporter: ReportGenerator):
    OPTS = {
        '1': 'View evidence list',
        '2': 'View evidence transaction history',
        '3': 'Export full chain-of-custody text report',
        '4': 'Export BSA Certificate of Authenticity',
        '5': 'Export evidence JSON report',
        'S': 'Blockchain summary & integrity check',
        '0': 'Logout',
    }
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        hdr(f'  COURT VIEWER MENU  ─  {user.name}  [{user.badge_id}]')
        rule()
        for k, v in OPTS.items():
            print(f"  {cc(GRN, k)}.  {v}")
        rule()
        ch = ask('Select').upper()

        if ch == '1':
            list_evidence(bc)
        elif ch == '2':
            _show_history(user, bc)
        elif ch == '3':
            eid = pick_evidence(bc)
            if eid: print(reporter.text_report(user, eid))
        elif ch == '4':
            eid = pick_evidence(bc)
            if eid: print(reporter.bsa_certificate(user, eid))
        elif ch == '5':
            eid = pick_evidence(bc)
            if eid:
                j     = reporter.json_report(user, eid)
                fname = f'report_{eid}.json'
                with open(fname, 'w') as f: f.write(j)
                ok(f'Saved → {fname}')
                print(j[:800] + '\n  …[truncated — see file]…' if len(j) > 800 else j)
        elif ch == 'S':
            print(cc(BLD, '\n  Blockchain summary:'))
            for blk in bc.chain:
                print(f"  Block #{blk['index']}  "
                      f"records={len(blk['records'])}  "
                      f"hash={MetadataBlockchain.hash(blk)[:32]}…")
            ok(f"Chain integrity: {'VALID ✓' if bc.verify_chain() else 'INVALID ✗'}")
        elif ch == '0':
            break
        else:
            warn('Invalid option.')

        if ch != '0':
            pause()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 20 — MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print(cc(CYN + BLD, """
  ╔══════════════════════════════════════════════════════════════════════╗
  ║                                                                      ║
  ║   NyayaChain — Blockchain Forensic Evidence Platform                 ║
  ║   Dissertation Final Prototype                                       ║
  ║                                                                      ║
  ║   Phases : 1=Police Seizure  2=Lab Analysis  3=IO Legal Mapping      ║
  ║   Legal  : BNS 2023 · BNSS 2023 · BSA 2023 · IT Act 2000            ║
  ║   Fabric : Hyperledger (simulated) — AES-CBC encrypted records       ║
  ║                                                                      ║
  ╚══════════════════════════════════════════════════════════════════════╝
"""))

    bc       = MetadataBlockchain()
    reporter = ReportGenerator(bc)
    ok('Blockchain initialised — genesis block created.')
    ok(f'AES encryption: {"enabled ✓" if _AES_AVAILABLE else "disabled (install pycryptodome)"}')
    print()

    while True:
        user = login(bc)

        if user.role == Role.POLICE:
            menu_police(user, bc, reporter)
        elif user.role == Role.FORENSIC_LAB:
            menu_lab(user, bc, reporter)
        elif user.role == Role.COURT_VIEWER:
            menu_court(user, bc, reporter)

        if ask('\n  Return to login screen? (y/n)').lower() != 'y':
            print(cc(CYN, '\n  Session ended. In-memory ledger discarded; export reports before exiting. Goodbye.\n'))
            break


if __name__ == '__main__':
    main()