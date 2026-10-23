"""Bounded, data-derived observations for supported evidence exports.

These parsers summarize evidence; they do not establish criminal attribution.
"""
import csv
import hashlib
import io
import json
import re
from collections import Counter
from email import policy
from email.parser import Parser
from pathlib import Path
from urllib.parse import unquote
from zipfile import ZipFile, BadZipFile

MAX_BYTES = 10 * 1024 * 1024
PROFILES = {'email', 'authentication', 'identity', 'network', 'inventory'}


def _read(meta, local_copy=None):
    location = local_copy or meta['url_or_path']
    if location.startswith(('http://', 'https://')):
        import requests
        with requests.get(location, stream=True, timeout=30) as response:
            response.raise_for_status()
            data = bytearray()
            for chunk in response.iter_content(8192):
                data.extend(chunk)
                if len(data) > MAX_BYTES:
                    raise ValueError('Evidence exceeds automatic analysis size limit; examine manually.')
        raw = bytes(data)
    else:
        with Path(location).open('rb') as handle:
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('Evidence exceeds automatic analysis size limit; examine manually.')
    digest = hashlib.sha256(raw).hexdigest()
    if digest != meta['sha256']:
        raise ValueError('Evidence integrity mismatch: bytes differ from registered SHA-256. Analysis not recorded.')
    return raw, digest


def _members(raw, filename):
    if raw.startswith(b'PK') or filename.lower().endswith('.zip'):
        try:
            with ZipFile(io.BytesIO(raw)) as archive:
                infos = [item for item in archive.infolist() if not item.is_dir()]
                if len(infos) > 100 or sum(item.file_size for item in infos) > MAX_BYTES:
                    raise ValueError('Archive exceeds automatic analysis limits; examine manually.')
                for info in infos:
                    if info.flag_bits & 1:
                        yield info.filename, None, 'Encrypted ZIP member requires manual examination.'
                    elif info.file_size > MAX_BYTES:
                        yield info.filename, None, 'Member exceeds analysis limit.'
                    else:
                        yield info.filename, archive.read(info), None
        except BadZipFile as error:
            raise ValueError('Invalid ZIP evidence.') from error
    else:
        yield filename, raw, None


def _records(text, suffix):
    if suffix == '.csv':
        return [dict(row) for row in csv.DictReader(io.StringIO(text))]
    if suffix == '.json':
        value = json.loads(text)
        if isinstance(value, dict):
            value = value.get('records', value.get('events', [value]))
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise ValueError('Expected a JSON object/list, or records/events array of objects.')
        return value
    if suffix in ('.jsonl', '.ndjson'):
        values = [json.loads(line) for line in text.splitlines() if line.strip()]
        if any(not isinstance(row, dict) for row in values):
            raise ValueError('Each JSONL line must be an object.')
        return values
    # Supported text log schema: key=value pairs, with optional ISO timestamp.
    rows = []
    for line in text.splitlines():
        pairs = dict(re.findall(r'([\w]+)=([^\s]+)', line))
        if pairs:
            if re.match(r'^\d{4}-\d\d-\d\dT', line):
                pairs.setdefault('timestamp', line.split()[0])
            rows.append(pairs)
    return rows


def _normalize(row):
    return {str(key).strip().lower(): str(value).strip() for key, value in row.items() if key is not None and value is not None}


def _first(row, *names):
    return next((row[name] for name in names if row.get(name)), '')


def analyze_evidence(meta, profile, local_copy=None):
    if profile not in PROFILES:
        raise ValueError('Choose one supported analysis profile.')
    raw, digest = _read(meta, local_copy)
    files, observations, skipped = [], [], []
    for name, content, error in _members(raw, meta.get('filename', 'evidence')):
        if error:
            skipped.append({'source': name, 'reason': error})
            continue
        suffix = Path(name).suffix.lower()
        if suffix not in ('.csv', '.json', '.jsonl', '.ndjson', '.txt', '.log', '.eml'):
            skipped.append({'source': name, 'reason': 'Unsupported format; manual examination required.'})
            continue
        try:
            text = content.decode('utf-8-sig')
            rows = [_normalize(row) for row in _records(text, suffix)]
        except (UnicodeError, ValueError, csv.Error) as error:
            skipped.append({'source': name, 'reason': f'Cannot parse supported export: {error}'})
            continue
        files.append({'source': name, 'sha256': hashlib.sha256(content).hexdigest(), 'parsed_rows': len(rows)})
        if profile == 'email':
            message = Parser(policy=policy.default).parsestr(text, headersonly=True)
            values = {key: [str(v) for v in message.get_all(key, [])] for key in
                      ('Date', 'From', 'To', 'Message-ID', 'Received', 'X-Originating-IP', 'Authentication-Results') if message.get_all(key)}
            if values:
                observations.append({'source': name, 'kind': 'email_headers', 'values': values,
                                     'interpretation': 'Header values are observed claims; sender identity is not authenticated by extraction.'})
        elif profile == 'authentication':
            relevant = [row for row in rows if _first(row, 'result', 'status', 'outcome') and _first(row, 'user', 'username', 'account')]
            if relevant:
                results = Counter(_first(row, 'result', 'status', 'outcome').upper() for row in relevant)
                failures = sum(count for key, count in results.items() if key in ('FAILED', 'FAILURE', 'FAIL', 'DENIED', 'INVALID'))
                successes = sum(count for key, count in results.items() if key in ('SUCCESS', 'SUCCESSFUL', 'ACCEPTED', 'OK'))
                observations.append({'source': name, 'kind': 'authentication_summary', 'events': len(relevant),
                                     'failures': failures, 'successes': successes, 'outcomes': dict(results),
                                     'users': sorted({_first(row, 'user', 'username', 'account') for row in relevant}),
                                     'source_ips': sorted({_first(row, 'source_ip', 'src_ip', 'ip', 'source') for row in relevant} - {''}),
                                     'interpretation': 'Counts describe exported events; they do not prove unauthorized access.'})
        elif profile == 'identity':
            relevant = [row for row in rows if _first(row, 'imsi', 'imei', 'device', 'device_id', 'peer', 'caller', 'callee')]
            if relevant:
                identifiers = {key: sorted({row[key] for row in relevant if row.get(key)}) for key in
                               ('imsi', 'imei', 'device', 'device_id', 'peer', 'caller', 'callee')}
                pairs = Counter((_first(row, 'device', 'device_id', 'caller'), _first(row, 'peer', 'callee')) for row in relevant
                                if _first(row, 'device', 'device_id', 'caller') and _first(row, 'peer', 'callee'))
                observations.append({'source': name, 'kind': 'identity_metadata', 'rows': len(relevant),
                                     'identifiers': {k: v for k, v in identifiers.items() if v},
                                     'communication_pairs': [{'device': a, 'peer': b, 'events': count} for (a, b), count in sorted(pairs.items())],
                                     'interpretation': 'Shared identifiers and repeated pairs are correlations, not proof of identity theft.'})
        elif profile == 'network':
            flows = [row for row in rows if _first(row, 'destination', 'dst_ip', 'dest_ip')]
            if flows:
                total, invalid = 0, 0
                for row in flows:
                    try:
                        size = int(_first(row, 'bytes', 'size_bytes', 'bytes_sent'))
                        if size < 0:
                            raise ValueError('negative byte count')
                        total += size
                    except ValueError:
                        invalid += 1
                observations.append({'source': name, 'kind': 'network_metadata', 'flows': len(flows),
                                     'destinations': sorted({_first(row, 'destination', 'dst_ip', 'dest_ip') for row in flows}),
                                     'sum_valid_byte_counts': total, 'missing_or_invalid_byte_counts': invalid,
                                     'interpretation': 'Destination/volume observations do not identify Tor nodes or establish exfiltration.'})
            web = [row for row in rows if _first(row, 'path', 'url', 'request', 'query')]
            if web:
                markers = []
                for index, row in enumerate(web, 1):
                    request = unquote(_first(row, 'path', 'url', 'request', 'query'))
                    if re.search(r"union\s+select|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|sql_injection_marker", request, re.I):
                        markers.append({'parsed_row': index, 'request': request})
                observations.append({'source': name, 'kind': 'web_request_review', 'requests': len(web),
                                     'sql_like_markers': markers,
                                     'interpretation': 'Simple signature matches are review leads; absence of a match does not rule out attacks and matches do not establish exploitation.'})
        elif profile == 'inventory':
            observations.append({'source': name, 'kind': 'file_inventory', 'bytes': len(content), 'parsed_rows': len(rows)})
    status = 'OBSERVATIONS_AVAILABLE' if observations else 'MANUAL_EXAMINATION_REQUIRED'
    return {'engine': 'NyayaChain export parser v1', 'profile': profile, 'evidence_sha256': digest,
            'status': status, 'files': files, 'observations': observations, 'skipped': skipped,
            'limitations': 'Only supported exports are summarized. No forensic acquisition, external tool execution, legal certification or criminal attribution is performed.'}


def format_analysis(result):
    return json.dumps(result, indent=2, ensure_ascii=False)
