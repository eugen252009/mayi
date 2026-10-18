"""Approver-role live aggregate status; no PAM, sessions or view operations."""
import argparse
import datetime
import errno
import json
import math
import os
import shutil
import signal
import sys
import time

from .executor import ExecutorError, RustApprovalAuthorityClient

COUNTERS = ('pending_approval', 'waiting_dependency', 'approved_ready',
            'awaiting_consumption', 'dispatching', 'running')
OTHER = ('blocked_terminal', 'outcome_unknown_terminal')
KEYS = set(COUNTERS + OTHER + ('ok', 'protocol', 'response_to', 'schema_version',
    'broker', 'broker_instance_id', 'snapshot_unix_ms', 'scope', 'total_active'))


class StatusError(Exception):
    def __init__(self, code, broker, message):
        super().__init__(message)
        self.code, self.broker = code, broker


def validate(value):
    if not isinstance(value, dict) or set(value) != KEYS:
        raise ExecutorError('invalid queue snapshot fields')
    if value['ok'] is not True or type(value['protocol']) is not int or value['protocol'] != 5 or value['response_to'] != 'QUEUE_STATUS':
        raise ExecutorError('invalid queue snapshot envelope')
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['broker'] != 'ONLINE' or value['scope'] != 'approver_global_aggregate':
        raise ExecutorError('invalid queue snapshot schema')
    identity = value['broker_instance_id']
    if not isinstance(identity, str) or len(identity) != 48 or any(c not in '0123456789abcdef' for c in identity):
        raise ExecutorError('invalid broker identity')
    for key in COUNTERS + OTHER + ('total_active',):
        if type(value[key]) is not int or not 0 <= value[key] <= 136:
            raise ExecutorError('invalid queue snapshot count')
    if value['total_active'] != sum(value[k] for k in COUNTERS):
        raise ExecutorError('inconsistent queue snapshot sum')
    if value['total_active'] + sum(value[k] for k in OTHER) > 136:
        raise ExecutorError('inconsistent retained snapshot bounds')
    stamp = value['snapshot_unix_ms']
    if type(stamp) is not int or not 0 <= stamp < 253402300800000:
        raise ExecutorError('invalid snapshot time')
    return value


def fetch():
    try:
        client = RustApprovalAuthorityClient('/run/mayi/approval/broker.sock', timeout=2, expected_broker_uid=23002)
        return validate(client._call({'type': 'QUEUE_STATUS'}))
    except PermissionError:
        raise StatusError(13, 'UNAVAILABLE', 'Approver access denied; no elevation attempted.')
    except ExecutorError as error:
        if any(s in str(error) for s in ('UNAUTHORIZED', 'unexpected broker peer UID')):
            raise StatusError(13, 'UNAVAILABLE', 'Approver role or trusted broker check failed.')
        raise StatusError(15, 'UNAVAILABLE', 'Invalid, unsupported or rejected broker snapshot.')
    except OSError as error:
        health = 'OFFLINE' if error.errno in (errno.ENOENT, errno.ECONNREFUSED) else 'UNAVAILABLE'
        raise StatusError(15, health, 'Broker snapshot unavailable; counters are not known.')


def public(value):
    result = {key: value[key] for key in ('schema_version','broker','broker_instance_id',
              'scope','snapshot_unix_ms') + COUNTERS + OTHER + ('total_active',)}
    result['snapshot_time'] = datetime.datetime.fromtimestamp(value['snapshot_unix_ms']/1000, datetime.timezone.utc).isoformat(timespec='milliseconds')
    return result


def preflight(value=None, error=None):
    if error is not None:
        return dict(schema_version=1, preflight='UNKNOWN', broker=error.broker,
                    error=dict(code=error.code,message=str(error))), 4
    result = dict(value)
    outcome = 'BUSY' if result['total_active'] else 'UNKNOWN' if result['outcome_unknown_terminal'] else 'READY'
    result.update(preflight=outcome, preflight_schema_version=1,
                  admission_fenced=False, physical_processes_verified=False)
    return result, {'READY':0,'BUSY':3,'UNKNOWN':4}[outcome]


def terminal_size():
    try:
        size=os.get_terminal_size(sys.stdout.fileno())
        if size.columns>0 and size.lines>0:return size
    except (OSError,ValueError,AttributeError):pass
    size=shutil.get_terminal_size((80,24))
    # Python3.9 may return a real but unsized PTY's 0x0 instead of fallback.
    return os.terminal_size((size.columns if size.columns>0 else 80,
                             size.lines if size.lines>0 else 24))


def render(value=None, error=None, width=None, details=False, height=None):
    width = max(20, min(120, width or terminal_size().columns))-1
    lines = ['MAYI - Approval Status', 'Broker: ' + (value['broker'] if value else error.broker)]
    if value:
        lines.append('Epoch: '+value['broker_instance_id'][:12]+'...')
        if 'preflight' in value:
            lines.append('Update preflight: '+value['preflight']+' (not an idle lock)')
        if details:
            labels = [('Pending approval','pending_approval'),('Waiting on dependencies','waiting_dependency'),
                      ('Approved / ready','approved_ready'),('Awaiting requester consume','awaiting_consumption'),
                      ('Dispatching / unconfirmed start','dispatching'),('Running (observed start)','running'),
                      ('Total active requests','total_active')]
            lines += ['{:<31} {}'.format(label+':',value[key]) for label,key in labels]
        else:
            pending,running,total = value['pending_approval'],value['running'],value['total_active']
            lines.append('Approval: {} waiting'.format(pending) if pending else 'No pending approvals.')
            if total:
                lines.append('Execution: {} running'.format(running))
                other=total-pending-running
                if other or value['dispatching']:
                    lines.append('Other: {}; dispatch: {}'.format(other,value['dispatching']))
                lines.append('{} active requests'.format(total))
            else:lines.append('No active requests.')
        if value['blocked_terminal'] or value['outcome_unknown_terminal']:
            lines.append('Blocked {} | Unknown {}'.format(value['blocked_terminal'],value['outcome_unknown_terminal']))
        if height is None:lines.append('Snapshot only; not a process inventory.')
    else:
        lines += ['Counters: UNAVAILABLE',str(error)]
    return '\n'.join(line[i:i+width] for line in lines for i in (range(0,len(line),width) if line else [0]))+'\n'


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    want_json = '--json' in argv
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise StatusError(12,'UNAVAILABLE','Invalid status arguments; see mayi-approve status --help.')
    parser = Parser(prog='mayi-approve status',description='Read-only approver snapshot; no PAM or approval session.')
    parser.add_argument('--json',action='store_true',help='JSON; --watch produces one JSON object per line')
    parser.add_argument('--preflight',action='store_true',help='read-only update observation: READY=0, BUSY=3, UNKNOWN=4; not an idle lock')
    parser.add_argument('--details',action='store_true',help='all authoritative counters in human output; JSON always contains all counters')
    parser.add_argument('--plain',action='store_true',help='with --watch: append-only human snapshots, no ANSI or TTY requirement')
    parser.add_argument('--watch',action='store_true',help='one-second snapshots; human mode requires a supported TTY')
    parser.add_argument('--interval',type=float,default=None,help='watch refresh seconds, 0.5..60')
    terminal = False
    previous = {}
    try:
        args = parser.parse_args(argv)
        if args.plain and (not args.watch or args.json):
            raise StatusError(12,'UNAVAILABLE','--plain requires human --watch; use --watch --json for machine output.')
        if args.preflight and args.watch:
            raise StatusError(12,'UNAVAILABLE','--preflight cannot be combined with --watch.')
        if args.interval is not None and (not args.watch or not math.isfinite(args.interval) or not .5 <= args.interval <= 60):
            raise StatusError(12,'UNAVAILABLE','--interval requires --watch and a finite value from 0.5 to 60.')
        if args.watch and not args.json and not args.plain:
            term = os.environ.get('TERM','')
            if not sys.stdout.isatty() or not term.startswith(('xterm','screen','tmux','vt','linux')):
                raise StatusError(12,'UNAVAILABLE','Human watch needs an ANSI-capable TTY; use --watch --plain without ANSI, or --watch --json for pipes.')
            terminal = True
            sys.stdout.write('\x1b[?1049h\x1b[?25l');sys.stdout.flush()
        if args.watch:
            def stop(signum, frame):raise KeyboardInterrupt
            for sig in (signal.SIGTERM,signal.SIGHUP):
                previous[sig]=signal.signal(sig,stop)
        last = None
        while True:
            value = error = None
            try:value = public(fetch())
            except StatusError as failure:error = failure
            if args.preflight:
                record, code = preflight(value,error)
                if args.json:print(json.dumps(record,sort_keys=True,ensure_ascii=True),flush=True)
                else:
                    print('Update preflight: UNKNOWN' if error else render(record,details=args.details),end='\n' if error else '')
                    if error:print(str(error),file=sys.stderr)
                return code
            if args.json:
                record = value if value is not None else dict(schema_version=1,broker=error.broker,error=dict(code=error.code,message=str(error)))
                print(json.dumps(record,sort_keys=True,ensure_ascii=True),flush=True)
            else:
                size=terminal_size()
                text = render(value,error,details=args.details,height=size.lines if terminal else None)
                if terminal and len(text.splitlines())>size.lines:
                    raise StatusError(12,'UNAVAILABLE','Snapshot does not fit this terminal; resize or use --watch --plain (and --details if needed).')
                # Snapshot time is intentionally not in the human canvas; unchanged counts need no repaint.
                if text != last:
                    sys.stdout.write(('\x1b[H\x1b[J' if terminal else ('Snapshot '+(value['snapshot_time'] if value else 'unavailable')+'\n' if args.plain else ''))+text);sys.stdout.flush();last=text
            if not args.watch:return error.code if error else 0
            time.sleep(args.interval or 1)
    except StatusError as error:
        if terminal:
            # Leave alternate screen BEFORE explaining a human-mode error.
            sys.stdout.write('\x1b[?25h\x1b[?1049l');sys.stdout.flush();terminal=False
        if want_json:print(json.dumps(dict(schema_version=1,broker=error.broker,error=dict(code=error.code,message=str(error))),sort_keys=True))
        else:print('MAYI_STATUS_ERROR: '+str(error),file=sys.stderr)
        return error.code
    except KeyboardInterrupt:return 130
    except BrokenPipeError:return 0
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)
        if terminal:
            sys.stdout.write('\x1b[?25h\x1b[?1049l');sys.stdout.flush()
