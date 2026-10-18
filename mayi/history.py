"""Bounded, unprivileged projection of native Mayi journal records. No broker IO."""
import argparse
import datetime as dt
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import time
from .recovery import classify_recovery
from .request_ids import REQUEST_ID_PATTERN,encoded_epoch

JOURNALCTL = '/usr/bin/journalctl'
MAX_RECORDS = 20000
MAX_BYTES = 16 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_GROUPS = 2000
TIMEOUT = 20
UNITS = {'mayi-broker.service': '23002', 'mayi-pam-auth.service': '0',
         'mayi-privileged-executor.service': '0'}
HEX = {32: re.compile(r'^[0-9a-f]{32}$'), 48: re.compile(r'^[0-9a-f]{48}$'),
       64: re.compile(r'^[0-9a-f]{64}$')}
RQ = re.compile('^'+REQUEST_ID_PATTERN+'$')
EVENT = re.compile(r'^[A-Z][A-Z0-9_]{0,63}$')
CH = re.compile(r'^ch_[0-9a-f]{48}$')
# Only typed lifecycle observations from the credential/unit-checked broker
# establish requests. A session/login/health/error record is not a proposal.
REQUEST_EVENTS = frozenset({
    'PROPOSED', 'QUEUE_SUBMITTED', 'REQUEST_INVALIDATED', 'VIEW_CREATED', 'VIEW_REPLACED',
    'VIEW_EXPIRED', 'VIEW_APPROVED', 'VIEW_DENIED', 'VIEW_EXPLAINED',
    'EXPIRED', 'CONSUMED', 'QUEUE_DISPATCH_STARTED', 'QUEUE_EXECUTION_FINISHED',
    'QUEUE_DISPATCH_FAILED', 'QUEUE_EXECUTION_OUTCOME_UNKNOWN', 'QUEUE_BLOCKED',
    'EXECUTION_DISPATCH_STARTED', 'EXECUTION_FINISHED', 'EXECUTION_DISPATCH_FAILED',
    'EXECUTION_OUTCOME_UNKNOWN',
})
FIELDS = {'request_id': 'MAYI_REQUEST_ID', 'broker_instance_id': 'MAYI_BROKER_INSTANCE_ID',
          'challenge_id': 'MAYI_CHALLENGE_ID', 'request_digest': 'MAYI_REQUEST_DIGEST',
          'execution_id': 'MAYI_EXECUTION_ID', 'state': 'MAYI_STATE',
          'requester_uid': 'MAYI_REQUESTER_UID', 'approver_uid': 'MAYI_APPROVER_UID',
          'result': 'MAYI_RESULT', 'exit_code': 'MAYI_CHILD_EXIT_STATUS',
          'signal': 'MAYI_CHILD_SIGNAL'}
NUMBERS = {'requester_uid', 'approver_uid', 'result', 'exit_code', 'signal'}
ALIASES = {'SUCCESS': 'SUCCEEDED', 'FAILURE': 'FAILED', 'PENDING_APPROVAL': 'PENDING',
           'PROPOSED': 'PENDING', 'READY': 'APPROVED', 'WAITING_DEPENDENCY': 'APPROVED',
           'EXECUTION_UNKNOWN': 'UNKNOWN', 'EXPLAINED': 'EXPLAIN_REQUESTED'}
STATES = {'PENDING', 'APPROVED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'DENIED',
          'EXPIRED', 'UNKNOWN', 'BLOCKED', 'EXPLAIN_REQUESTED', 'INVALIDATED'}


class HistoryError(Exception):
    def __init__(self, code, name, message):
        super().__init__(message)
        self.code, self.name = code, name


def invalid(message):
    return HistoryError(12, 'INVALID_ARGUMENT', message)


def safe(text, width=120):
    # ASCII only: escape bidi, terminal controls and embedded newlines as well.
    result = str(text).encode('unicode_escape').decode('ascii')
    return result if len(result) <= width else result[:max(0, width - 3)] + '...'


def arguments(argv):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise invalid('invalid history arguments (see mayi history --help)')
    p = Parser(prog='mayi history', description='Read-only journal history, never live broker state.')
    limits = p.add_mutually_exclusive_group()
    limits.add_argument('--limit', type=int, default=20, metavar='N', help='1..1000 requests (default 20)')
    limits.add_argument('--all', action='store_true', help='all within scan bounds, at most 2000 identities')
    p.add_argument('--status', type=str.upper, help='status or last observed nonterminal state')
    p.add_argument('--request', help='full rq_ or ch_ ID; show each boot/instance/binding separately')
    p.add_argument('--epoch', help='full existing 48-hex broker instance ID')
    p.add_argument('--events', action='store_true', help='chronological native audit events, not request rows')
    p.add_argument('--since', help='journalctl timestamp, e.g. "1 hour ago"')
    p.add_argument('--json', action='store_true', help='stable schema v2 JSON')
    a = p.parse_args(argv)
    if not 1 <= a.limit <= 1000:
        raise invalid('--limit must be between 1 and 1000')
    if a.request and not (RQ.fullmatch(a.request) or CH.fullmatch(a.request)):
        raise invalid('--request requires a full legacy rq_, rq_v2_ or ch_ identity')
    if a.epoch and not HEX[48].fullmatch(a.epoch):
        raise invalid('--epoch requires full 48-lowercase-hex broker instance ID')
    if a.since and (len(a.since) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in a.since)):
        raise invalid('--since must be a bounded single-line journal timestamp')
    if a.status:
        a.status = ALIASES.get(a.status, a.status)
        if a.status not in STATES:
            raise invalid('unsupported history status')
    return a


def command(since=None):
    argv = [JOURNALCTL, '--no-pager', '--output=json', '--reverse',
            '--lines=' + str(MAX_RECORDS), '--all']
    if since:
        argv.append('--since=' + since)
    for i, (unit, uid) in enumerate(UNITS.items()):
        if i:
            argv.append('+')
        argv.extend(['SYSLOG_IDENTIFIER=mayi', 'MAYI_SCHEMA_VERSION=1',
                     '_TRANSPORT=journal', '_SYSTEMD_UNIT=' + unit, '_UID=' + uid])
    return argv


def read_journal(since=None):
    """Drain both pipes incrementally; never retain arbitrary journal messages."""
    try:
        process = subprocess.Popen(command(since), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env={'LC_ALL': 'C', 'LANG': 'C',
                                                               'SYSTEMD_COLORS': '0'})
    except PermissionError:
        raise HistoryError(13, 'JOURNAL_ACCESS_DENIED', 'Journal access denied; existing reader permissions are required.')
    except OSError:
        raise HistoryError(15, 'JOURNAL_UNAVAILABLE', 'Cannot start /usr/bin/journalctl.')
    records, stderr, pending = [], bytearray(), bytearray()
    scanned = ignored = total = 0
    bounded = False
    selector = selectors.DefaultSelector()
    for pipe in (process.stdout, process.stderr):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
    deadline = time.monotonic() + TIMEOUT
    dropping = False
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise HistoryError(15, 'JOURNAL_TIMEOUT', 'Journal read exceeded the 20-second bound; narrow --since.')
            for key, _ in selector.select(min(.2, max(0, deadline - time.monotonic()))):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                total += len(data)
                if total > MAX_BYTES:
                    bounded = True
                    break
                if key.fileobj is process.stderr:
                    stderr.extend(data[:max(0, 8192 - len(stderr))])
                    continue
                pending.extend(data)
                while b'\n' in pending:
                    line, _, tail = pending.partition(b'\n');pending = bytearray(tail)
                    scanned += 1
                    if not dropping and len(line) <= MAX_LINE:
                        item = decode(line)
                        if item is not None:
                            records.append(item)
                        else:
                            ignored += 1
                    else:
                        ignored += 1
                    dropping = False
                    if scanned >= MAX_RECORDS:
                        bounded = True
                        break
                if len(pending) > MAX_LINE:
                    pending.clear();dropping = True
                if bounded:
                    break
            if bounded:
                break
        if bounded:
            process.terminate()
        try:
            code = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill();process.wait();code = -1
        try:
            stderr.extend(os.read(process.stderr.fileno(), max(0, 8192-len(stderr))))
        except BlockingIOError:
            pass
        diagnostic = stderr.decode('utf-8', 'replace').lower()
        if any(x in diagnostic for x in ('permission', 'access denied', 'not seeing messages')):
            raise HistoryError(13, 'JOURNAL_ACCESS_DENIED', 'Cannot read the complete system journal with existing permissions; no elevation attempted.')
        if not bounded and code:
            if 'parse timestamp' in diagnostic:
                raise invalid('journalctl could not parse --since')
            raise HistoryError(15, 'JOURNAL_READ_FAILED', 'journalctl failed; journal may be unavailable or corrupt.')
        if pending and not bounded:
            ignored += 1  # journalctl promises newline-delimited JSON
        return records, {'scanned_records': scanned, 'ignored_records': ignored,
                         'scan_truncated': bounded, 'bytes_read': total}
    finally:
        selector.close()
        if process.poll() is None:
            process.kill();process.wait()
        process.stdout.close();process.stderr.close()


def decode(line):
    try:
        raw = json.loads(line)
        if not isinstance(raw, dict) or raw.get('SYSLOG_IDENTIFIER') != 'mayi' or raw.get('_TRANSPORT') != 'journal' or raw.get('MAYI_SCHEMA_VERSION') != '1':
            return None
        unit = raw.get('_SYSTEMD_UNIT')
        if not isinstance(unit, str) or unit not in UNITS or raw.get('_UID') != UNITS[unit]:
            return None
        event, boot, stamp = raw.get('MAYI_EVENT'), raw.get('_BOOT_ID'), raw.get('__REALTIME_TIMESTAMP')
        if not isinstance(event, str) or not EVENT.fullmatch(event):
            return None
        if not isinstance(boot, str) or not HEX[32].fullmatch(boot):
            return None
        if not isinstance(stamp, str) or not re.fullmatch(r'[0-9]{1,18}', stamp):
            return None
        micros = int(stamp)
        timestamp = dt.datetime.fromtimestamp(micros / 1000000, dt.timezone.utc).astimezone().isoformat(timespec='microseconds')
        monotonic = raw.get('__MONOTONIC_TIMESTAMP')
        mono = int(monotonic) if isinstance(monotonic, str) and re.fullmatch(r'[0-9]{1,18}', monotonic) else micros
        cursor = raw.get('__CURSOR')
        if not isinstance(cursor, str) or len(cursor) > 256 or not cursor.isascii() or any(ord(c) < 32 for c in cursor):
            cursor = None
        out = dict(event=event, timestamp=timestamp, boot_id=boot, source_unit=unit,
                   _time=micros, _order=mono, _cursor=cursor)
        for key, name in FIELDS.items():
            value = raw.get(name)
            if value is None:
                out[key] = None
                continue
            if not isinstance(value, str) or len(value) > 256:
                return None
            if key in NUMBERS:
                if not re.fullmatch(r'0|[1-9][0-9]{0,9}', value):
                    return None
                value = int(value)
                ceiling = 255 if key in ('result', 'exit_code') else 64 if key == 'signal' else 4294967295
                if value > ceiling or (key == 'signal' and value == 0):return None
            elif key == 'request_id':
                if not RQ.fullmatch(value):return None
            elif key in ('broker_instance_id', 'challenge_id', 'request_digest', 'execution_id'):
                size = 64 if key == 'request_digest' else 32 if key == 'execution_id' else 48
                if not HEX[size].fullmatch(value):return None
            elif key == 'state' and not EVENT.fullmatch(value):
                return None
            out[key] = value
        # Only the broker can provide an authoritative queue identity/bridge.
        if unit != 'mayi-broker.service':
            out['request_id'] = None
        out['invalidation_reason'] = 'BROKER_STOPPING' if event == 'REQUEST_INVALIDATED' and raw.get('MAYI_REASON') == 'BROKER_STOPPING' else None
        return out
    except (ValueError, TypeError, OverflowError, OSError, RecursionError):
        return None


def request_anchor(row):
    if row['request_id'] and encoded_epoch(row['request_id']):
        if encoded_epoch(row['request_id'])!=row['broker_instance_id'] or row['request_id'].split('_')[4]!=row['request_digest']:return False
    return (row['source_unit'] == 'mayi-broker.service'
            and row['event'] in REQUEST_EVENTS and row['broker_instance_id']
            and row['challenge_id'] and row['request_digest']
            and row['requester_uid'] is not None)


def _partition(records, maximum=MAX_GROUPS):
    """One bounded correlation model shared by requests, detail and event mode."""
    anchors, queue_bindings = {}, {}
    def binding(row):
        return (row['boot_id'], row['broker_instance_id'], row['challenge_id'], row['request_digest'])
    for index, row in enumerate(records):
        if not request_anchor(row):
            continue
        identity = row['request_id'] or 'ch_' + row['challenge_id']
        key = (row['boot_id'], row['broker_instance_id'], identity,
               row['challenge_id'], row['request_digest'])
        anchors[index] = key
        if row['request_id']:
            queue_bindings.setdefault(binding(row), set()).add(key)
    # Only an explicit unique binding can supply a missing queue ID.
    for index, key in list(anchors.items()):
        if not records[index]['request_id']:
            candidates = queue_bindings.get(binding(records[index]), set())
            if len(candidates) == 1:
                anchors[index] = next(iter(candidates))
    keys = dict.fromkeys(anchors.values())
    groups = {key: [] for key in list(keys)[:maximum]}
    bridges, challenges = {}, {}
    for index, key in anchors.items():
        row = records[index]
        challenges.setdefault(binding(row), set()).add(key)
        if row['execution_id']:
            bridges.setdefault((row['boot_id'], row['execution_id']), set()).add(key)
    links, overflow = [], 0
    for index, row in enumerate(records):
        key = anchors.get(index)
        if key is None and row['source_unit'] == 'mayi-broker.service':
            if row['request_id']:
                candidate = (row['boot_id'], row['broker_instance_id'], row['request_id'],
                             row['challenge_id'], row['request_digest'])
                if candidate in keys:
                    key = candidate
            if key is None and not row['request_id']:
                candidates = challenges.get(binding(row), set())
                if len(candidates) == 1:
                    key = next(iter(candidates))
        if key is None and row['source_unit'] == 'mayi-privileged-executor.service' and row['execution_id']:
            candidates = bridges.get((row['boot_id'], row['execution_id']), set())
            if row['broker_instance_id']:
                candidates={candidate for candidate in candidates if candidate[1]==row['broker_instance_id']}
            if len(candidates) == 1:
                key = next(iter(candidates))
        if key is None and row['source_unit'] == 'mayi-pam-auth.service':
            candidates = challenges.get(binding(row), set())
            if len(candidates) == 1:
                key = next(iter(candidates))
        links.append(key)
        if key in groups:
            groups[key].append(row)
        elif key is not None:
            overflow += 1
    return groups, links, overflow


def reconstruct(records, maximum=MAX_GROUPS, partition=None):
    groups, _, overflow = partition if partition is not None else _partition(records, maximum)
    result = []
    stops, starts = {}, {}
    for row in records:
        if row['source_unit']!='mayi-broker.service' or not row['broker_instance_id']:continue
        epoch=(row['boot_id'],row['broker_instance_id'])
        if row['event']=='BROKER_STOPPING':stops[epoch]=max(stops.get(epoch,-1),row['_order'])
        if row['event']=='BROKER_STARTED':
            table=starts.setdefault(row['boot_id'],{});table[row['broker_instance_id']]=max(table.get(row['broker_instance_id'],-1),row['_order'])
    latest={boot:sorted(((order,epoch) for epoch,order in table.items()),reverse=True)[:2] for boot,table in starts.items()}
    for key, rows in groups.items():
        if not rows:continue
        seen, events = set(), []
        for row in sorted(rows, key=lambda r: (r['_order'], r['_time'], r['event'], r['_cursor'] or '')):
            fingerprint = (row['source_unit'], row['_cursor']) if row['_cursor'] else json.dumps(row, sort_keys=True)
            if fingerprint in seen:continue
            seen.add(fingerprint);events.append(row)
        terminal, observed = set(), None
        code = child = sig = None
        for row in events:
            event, state, unit = row['event'], row['state'], row['source_unit']
            broker = unit == 'mayi-broker.service'
            executor = unit == 'mayi-privileged-executor.service'
            if (broker and event in ('QUEUE_EXECUTION_FINISHED', 'EXECUTION_FINISHED')) or (executor and event == 'EXECUTION_FINISHED'):
                if state == 'SUCCEEDED' and row['exit_code'] == 0 and (executor or row['result'] == 0):
                    terminal.add('SUCCEEDED')
                elif state == 'FAILED' and (row['exit_code'] not in (None, 0) or row['signal'] is not None or (broker and row['result'] == 14)):
                    terminal.add('FAILED')
                else:terminal.add('UNKNOWN')
                code, child, sig = row['result'] if broker else code, row['exit_code'], row['signal'] or sig
            elif broker and event in ('VIEW_DENIED', 'EXPIRED', 'QUEUE_BLOCKED', 'VIEW_EXPLAINED'):
                terminal.add({'VIEW_DENIED':'DENIED','EXPIRED':'EXPIRED','QUEUE_BLOCKED':'BLOCKED','VIEW_EXPLAINED':'EXPLAIN_REQUESTED'}[event])
                code = row['result']
            elif (broker and event in ('QUEUE_DISPATCH_FAILED', 'EXECUTION_DISPATCH_FAILED')) or (executor and event == 'EXECUTION_REJECTED'):
                terminal.add('FAILED');code = row['result'] if broker else code
            elif event in ('QUEUE_EXECUTION_OUTCOME_UNKNOWN', 'EXECUTION_OUTCOME_UNKNOWN'):
                # Not a conflicting terminal fact if an authoritative completion is also present.
                observed = 'UNKNOWN'
            elif broker and event in ('PROPOSED','QUEUE_SUBMITTED'):
                observed = 'PENDING'
            elif broker and event == 'VIEW_APPROVED':observed = 'APPROVED'
            elif (broker and event in ('QUEUE_DISPATCH_STARTED','EXECUTION_DISPATCH_STARTED')) or (executor and event == 'EXECUTION_STARTED'):
                observed = 'RUNNING'
        status = next(iter(terminal)) if len(terminal) == 1 else 'UNKNOWN'
        request_ids = {r['request_id'] for r in events if r['request_id']}
        request_id = next(iter(request_ids)) if len(request_ids) == 1 else None
        incomplete = status == 'UNKNOWN' or len(terminal) > 1
        public = [dict({k:v for k,v in row.items() if not k.startswith('_')},epoch_id=row['broker_instance_id']) for row in events]
        explicit = any(r['event']=='REQUEST_INVALIDATED' and r['state']=='INVALIDATED' and r.get('invalidation_reason')=='BROKER_STOPPING' for r in events)
        first_order=min(r['_order'] for r in events)
        stopped=stops.get((key[0],key[1]),-1)>=first_order
        successor=any(order>first_order and epoch!=key[1] for order,epoch in latest.get(key[0],[]))
        invalid=explicit or stopped or successor
        recovery=classify_recovery(public)
        result.append(dict(identity=key[2], request_id=request_id, challenge_id=key[3], request_digest=key[4], epoch_id=key[1],
                           authorization_state='INVALIDATED' if invalid else 'NOT_ESTABLISHED',
                           invalidation_reason='BROKER_STOPPING' if explicit or stopped else 'BROKER_RESTARTED' if successor else None,
                           invalidation_evidence='EXPLICIT_REQUEST_FENCE' if explicit else 'EPOCH_LIFECYCLE_INFERENCE' if invalid else None,
                           execution_outcome=status if recovery=='COMPLETED' else 'NOT_DISPATCHED' if recovery=='SAFE_TO_RECREATE_REQUEST' else 'UNKNOWN',
                           recovery_classification=recovery,
                           boot_id=key[0], broker_instance_id=key[1], status=status,
                           observed_state=status if status != 'UNKNOWN' else observed,
                           current_state_known=False, correlation_incomplete=incomplete,
                           result=code, exit_code=child, signal=sig,
                           requester_uid=next((r['requester_uid'] for r in reversed(events) if r['requester_uid'] is not None), None),
                           timestamp=max(events, key=lambda r:r['_time'])['timestamp'],
                           events=public, _latest=max(r['_time'] for r in events)))
    result.sort(key=lambda r:(-r['_latest'], r['boot_id'], r['broker_instance_id'] or '', r['identity']))
    for row in result:del row['_latest']
    return result, overflow


def event_rows(records, links):
    seen, events = set(), []
    for row, key in sorted(zip(records, links), key=lambda pair: (
            pair[0]['_time'], pair[0]['boot_id'], pair[0]['_order'],
            pair[0]['source_unit'], pair[0]['event'], pair[0]['_cursor'] or '')):
        fingerprint = (row['source_unit'], row['_cursor']) if row['_cursor'] else json.dumps(row, sort_keys=True)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        event = {k:v for k,v in row.items() if not k.startswith('_')}
        event.update(epoch_id=row['broker_instance_id'], correlated_epoch_id=key[1] if key else None,
                     request_identity=key[2] if key else None,
                     request_broker_instance_id=key[1] if key else None,
                     correlation_incomplete=key is None)
        events.append((event, key))
    return events


def document(records, stats, args):
    partition = _partition(records)
    rows, omitted = reconstruct(records, partition=partition)
    if args.request:
        rows = [r for r in rows if r['identity'] == args.request]
    if args.epoch:
        rows = [r for r in rows if r['epoch_id']==args.epoch]
    if args.status:
        rows = [r for r in rows if (args.status=='INVALIDATED' and r['authorization_state']=='INVALIDATED') or r['status'] == args.status or
                (r['status']=='UNKNOWN' and r['observed_state']==args.status)]
    output_events = []
    if args.events:
        allowed = {(r['boot_id'],r['broker_instance_id'],r['identity'],
                    r['challenge_id'],r['request_digest']) for r in rows}
        available = [event for event,key in event_rows(records, partition[1])
                     if ((not args.request and not args.status) or key in allowed)
                     and (not args.epoch or event['epoch_id']==args.epoch or (key is not None and key[1]==args.epoch))]
        matched = len(available)
        output_events = available[-(MAX_RECORDS if args.all else args.limit):]
        rows = []
        returned = len(output_events)
    else:
        matched = len(rows)
        rows = rows[:MAX_GROUPS if args.all or args.request else args.limit]
        returned = len(rows)
    return dict(schema_version=2, mode='events' if args.events else 'requests',
                count_unit='events' if args.events else 'requests',
                requests=rows, events=output_events, returned=returned, matched=matched,
                **stats, omitted_records=omitted,
                diagnostic_records=sum(key is None for key in partition[1]),
                limits=dict(records=MAX_RECORDS, bytes=MAX_BYTES, identities=MAX_GROUPS, seconds=TIMEOUT),
                historical_only=True, completeness='Best-effort retained journal window; not live broker state.')

def render(doc, detail=False, width=None):
    width = max(24, min(160, width or shutil.get_terminal_size((80,24)).columns))
    is_events = doc.get('mode') == 'events'
    lines = ['MAYI - Audit Events' if is_events else 'MAYI - Request History', '']
    previous_epoch=object()
    def epoch_separator(epoch, boot):
        nonlocal previous_epoch
        current=(boot,epoch)
        if current!=previous_epoch:
            if isinstance(previous_epoch,tuple):lines.append('--- NEW EPOCH ---' if epoch else '--- UNKNOWN EPOCH ---')
            lines.append('Epoch: '+(epoch[:12]+'...' if epoch else 'UNKNOWN (legacy/unassociated)'))
            previous_epoch=current
    if is_events:
        event_width = max(8, min(34, width-30))
        lines.append('{:<8}  {:<{ew}}  {}'.format('TIME','EVENT','REQUEST / ID',ew=event_width))
        for event in doc['events']:
            epoch_separator(event.get('epoch_id'),event['boot_id'])
            lines.append('{:<8}  {:<{ew}}  {}'.format(event['timestamp'][11:19],safe(event['event'],event_width),safe(event['request_identity'] or '-',18),ew=event_width))
    elif detail:
        for row in doc['requests']:
            epoch_separator(row.get('epoch_id'),row['boot_id'])
            lines.extend(['Request: ' + row['identity'], 'Boot: ' + row['boot_id'],
                          'Created in epoch: '+str(row.get('epoch_id') or 'UNKNOWN'),
                          'Current epoch: NOT QUERIED (history is not live state)',
                          'Authorization: '+str(row.get('authorization_state'))+'; reason: '+str(row.get('invalidation_reason')),
                          'Execution: '+str(row.get('execution_outcome'))+'; recovery: '+str(row.get('recovery_classification')),
                          'Broker: ' + (row['broker_instance_id'] or '-'),
                          'Status: ' + row['status'], 'Last observed: ' + (row['observed_state'] or '-'),
                          'Mayi code: ' + str(row['result']), 'Child exit: ' + str(row['exit_code']),
                          'Correlation: ' + ('incomplete' if row['correlation_incomplete'] else 'explicit broker mapping'), 'Timeline:'])
            lines.extend('  ' + r['timestamp'] + ' ' + r['event'] + ' ' + r['source_unit'] for r in row['events'])
            lines.append('')
    else:
        id_width = max(6, min(18, width - 30))
        lines.append('{:<8}  {:<{iw}}  {:<12} {}'.format('TIME','REQUEST / ID','STATUS','RESULT', iw=id_width))
        for row in doc['requests']:
            epoch_separator(row.get('epoch_id'),row['boot_id'])
            status = (row['observed_state'] or 'UNKNOWN') + '?' if row['status']=='UNKNOWN' else row['status']
            if row.get('recovery_classification')=='SAFE_TO_RECREATE_REQUEST':status='INVALIDATED'
            stamp = row['timestamp'][11:19]
            result = '-' if row['result'] is None else str(row['result'])
            identity = row['request_id'] or (row['events'][-1]['event'] if row['identity'].startswith('event_') else row['identity'])
            label = safe(identity, id_width)
            lines.append('{:<8}  {:<{iw}}  {:<12} {}'.format(stamp,label,status,result,iw=id_width))
    if not (doc['events'] if is_events else doc['requests']):lines.append('No matching retained events.' if is_events else 'No matching retained requests.')
    lines.extend(['', 'Showing {} of {} matched {}.'.format(doc['returned'],doc['matched'],doc['count_unit']),
                  '? = last observed only; current state UNKNOWN. No live broker query.',
                  'History may be incomplete (retention, restart, rate limits).'])
    if doc['scan_truncated'] or doc['omitted_records']:lines.append('Scan bound reached; narrow --since for more detail.')
    # Detail IDs remain available in full even on narrow terminals/JSON; wrap safely.
    output=[]
    for line in lines:
        escaped=safe(line,4096)
        output.extend(escaped[i:i+width] for i in range(0,len(escaped),width)) if escaped else output.append('')
    return '\n'.join(output)+'\n'


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    want_json = '--json' in argv
    try:
        args = arguments(argv)
        records, stats = read_journal(args.since)
        doc = document(records, stats, args)
        print(json.dumps(doc, sort_keys=True, ensure_ascii=True) if args.json else render(doc, bool(args.request)), end='\n' if args.json else '')
        return 0
    except HistoryError as error:
        if want_json:
            print(json.dumps(dict(schema_version=2,error=dict(code=error.name,message=str(error))),sort_keys=True))
        else:
            print('MAYI_HISTORY_ERROR: '+safe(str(error)),file=sys.stderr)
        return error.code
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
