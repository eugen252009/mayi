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
RQ = re.compile(r'^rq_[0-9a-f]{32}$')
EVENT = re.compile(r'^[A-Z][A-Z0-9_]{0,63}$')
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
          'EXPIRED', 'UNKNOWN', 'BLOCKED', 'EXPLAIN_REQUESTED'}


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
    p.add_argument('--request', help='full rq_ ID; show each boot/instance separately')
    p.add_argument('--since', help='journalctl timestamp, e.g. "1 hour ago"')
    p.add_argument('--json', action='store_true', help='stable schema v1 JSON')
    a = p.parse_args(argv)
    if not 1 <= a.limit <= 1000:
        raise invalid('--limit must be between 1 and 1000')
    if a.request and not RQ.fullmatch(a.request):
        raise invalid('--request requires a full rq_ plus 32 lowercase hex ID')
    if a.since and (len(a.since) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in a.since)):
        raise invalid('--since must be a bounded single-line journal timestamp')
    if a.status:
        a.status = ALIASES.get(a.status, a.status)
        if a.status not in STATES:
            raise invalid('unsupported history status')
    return a


def command(since=None):
    argv = [JOURNALCTL, '--system', '--no-pager', '--output=json', '--reverse',
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
        return out
    except (ValueError, TypeError, OverflowError, OSError, RecursionError):
        return None


def reconstruct(records, maximum=MAX_GROUPS):
    groups, bridges, challenges = {}, {}, {}
    def add_mapping(table, key, group):
        table.setdefault(key, set()).add(group)
    # All mappings must be explicit broker fields; never derive rq_ from execution IDs.
    for row in records:
        if row['source_unit'] != 'mayi-broker.service' or not row['broker_instance_id']:
            continue
        identity = row['request_id'] or ('ch_' + row['challenge_id'] if row['challenge_id'] else None)
        if not identity:
            continue
        key = (row['boot_id'], row['broker_instance_id'], identity)
        if len(groups) < maximum or key in groups:
            groups.setdefault(key, [])
        if row['execution_id']:
            add_mapping(bridges, (row['boot_id'], row['execution_id']), key)
        if row['challenge_id'] and row['request_digest']:
            add_mapping(challenges, (row['boot_id'], row['broker_instance_id'], row['challenge_id'], row['request_digest']), key)
    overflow = 0
    for index, row in enumerate(records):
        key = None
        if row['source_unit'] == 'mayi-broker.service' and row['broker_instance_id']:
            ident = row['request_id'] or ('ch_' + row['challenge_id'] if row['challenge_id'] else None)
            if ident:
                key = (row['boot_id'], row['broker_instance_id'], ident)
        if key is None and row['source_unit'] == 'mayi-privileged-executor.service' and row['execution_id']:
            candidates = bridges.get((row['boot_id'], row['execution_id']), set())
            if len(candidates) == 1:key = next(iter(candidates))
        if key is None and row['source_unit'] == 'mayi-pam-auth.service':
            candidates = challenges.get((row['boot_id'], row['broker_instance_id'], row['challenge_id'], row['request_digest']), set())
            if len(candidates) == 1:key = next(iter(candidates))
        if key is None:
            # Independently identifiable failures must not disappear. No timestamp/UID join.
            ident = 'ex_' + row['execution_id'] if row['execution_id'] else 'event_' + str(index)
            key = (row['boot_id'], row['broker_instance_id'], ident)
        if key not in groups and len(groups) >= maximum:
            overflow += 1;continue
        groups.setdefault(key, []).append(row)
    result = []
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
        incomplete = not request_id or not key[1] or status == 'UNKNOWN' or len(terminal) > 1
        public = [{k:v for k,v in row.items() if not k.startswith('_')} for row in events]
        result.append(dict(identity=key[2], request_id=request_id,
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


def document(records, stats, args):
    rows, omitted = reconstruct(records)
    if args.request:rows = [r for r in rows if r['request_id'] == args.request]
    if args.status:rows = [r for r in rows if r['status'] == args.status or (r['status']=='UNKNOWN' and r['observed_state']==args.status)]
    matched = len(rows)
    rows = rows[:MAX_GROUPS if args.all or args.request else args.limit]
    return dict(schema_version=1, requests=rows, returned=len(rows), matched=matched,
                **stats, omitted_records=omitted, limits=dict(records=MAX_RECORDS, bytes=MAX_BYTES, identities=MAX_GROUPS, seconds=TIMEOUT),
                historical_only=True, completeness='Best-effort retained journal window; not live broker state.')


def render(doc, detail=False, width=None):
    width = max(24, min(160, width or shutil.get_terminal_size((80,24)).columns))
    lines = ['MAYI - Request History', '']
    if detail:
        for row in doc['requests']:
            lines.extend(['Request: ' + row['identity'], 'Boot: ' + row['boot_id'],
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
            status = (row['observed_state'] or 'UNKNOWN') + '?' if row['status']=='UNKNOWN' else row['status']
            stamp = row['timestamp'][11:19]
            result = '-' if row['result'] is None else str(row['result'])
            identity = row['request_id'] or (row['events'][-1]['event'] if row['identity'].startswith('event_') else row['identity'])
            label = safe(identity, id_width)
            lines.append('{:<8}  {:<{iw}}  {:<12} {}'.format(stamp,label,status,result,iw=id_width))
    if not doc['requests']:lines.append('No matching retained events.')
    lines.extend(['', 'Showing {} of {} matched identities.'.format(doc['returned'],doc['matched']),
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
            print(json.dumps(dict(schema_version=1,error=dict(code=error.name,message=str(error))),sort_keys=True))
        else:
            print('MAYI_HISTORY_ERROR: '+safe(str(error)),file=sys.stderr)
        return error.code
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
