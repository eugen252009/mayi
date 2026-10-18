import io
import json
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from mayi import history as h
from mayi.cli import main as cli


def raw(event='QUEUE_SUBMITTED', **fields):
    row = dict(SYSLOG_IDENTIFIER='mayi', MAYI_SCHEMA_VERSION='1', _TRANSPORT='journal',
               _SYSTEMD_UNIT='mayi-broker.service', _UID='23002', _BOOT_ID='a'*32,
               __REALTIME_TIMESTAMP='1792306800000000', __MONOTONIC_TIMESTAMP='1000000',
               MAYI_EVENT=event, MAYI_REQUEST_ID='rq_'+'1'*32,
               MAYI_BROKER_INSTANCE_ID='b'*48, MAYI_CHALLENGE_ID='c'*48,
               MAYI_REQUEST_DIGEST='d'*64, MAYI_REQUESTER_UID='1000', MAYI_STATE='PENDING_APPROVAL')
    row.update(fields)
    return row


def event(name='QUEUE_SUBMITTED', **fields):
    return h.decode(json.dumps(raw(name, **fields)))


def options(*args):
    return h.arguments(list(args))


def doc(events, *args):
    return h.document(events, dict(scanned_records=len(events),ignored_records=0,scan_truncated=False,bytes_read=100), options(*args))


def done(**fields):
    return event('QUEUE_EXECUTION_FINISHED', MAYI_STATE='SUCCEEDED', MAYI_RESULT='0',MAYI_CHILD_EXIT_STATUS='0',**fields)


def test_default_unknown_is_not_live_pending():
    d=doc([event()]);r=d['requests'][0]
    assert r['status']=='UNKNOWN' and r['observed_state']=='PENDING' and not r['current_state_known']
    assert 'PENDING?' in h.render(d) and 'not live' in h.render(d).lower() or 'No live' in h.render(d)


@pytest.mark.parametrize('args', [['--limit','0'],['--limit','1001'],['--limit','-1'],['--limit','no'],['--all','--limit','5'],['--status','canceled'],['--request','rq_x'],['--request','rq_'+'a'*33],['--since','x\n\x1b'],['--since','x'*257],['--wat']])
def test_invalid(args):
    with pytest.raises(h.HistoryError) as exc:options(*args)
    assert exc.value.code==12


def test_limit_order_and_no_duplicate_requests():
    rows=[done(MAYI_REQUEST_ID='rq_'+format(i,'032x'), __REALTIME_TIMESTAMP=str(1792306800000000+i)) for i in range(30)]
    d=doc(rows*2);assert d['returned']==20 and d['matched']==30
    assert d['requests'][0]['request_id']=='rq_'+format(29,'032x')
    assert doc(rows,'--all')['returned']==30
    assert doc(rows,'--limit','2')['returned']==2
    assert len(doc([done(),done()])['requests'][0]['events'])==1


def test_filters_and_json(capsys,monkeypatch):
    monkeypatch.setattr(h,'read_journal',lambda since:([done()],dict(scanned_records=1,ignored_records=0,scan_truncated=False,bytes_read=1)))
    assert cli(['history','--json','--status','success','--since','1 hour ago'])==0
    value=json.loads(capsys.readouterr().out)
    assert value['schema_version']==1 and value['requests'][0]['exit_code']==0
    assert doc([event()],'--status','pending')['returned']==1
    assert doc([done()],'--status','failed')['returned']==0
    assert doc([done()],'--request','rq_'+'2'*32)['returned']==0


def test_missing_finish_and_view_expiry_do_not_prove_expiration():
    assert doc([event('VIEW_APPROVED')])['requests'][0]['status']=='UNKNOWN'
    assert doc([event('QUEUE_DISPATCH_STARTED')])['requests'][0]['observed_state']=='RUNNING'
    assert doc([event('VIEW_EXPIRED')])['requests'][0]['status']=='UNKNOWN'
    assert doc([event('EXPIRED')])['requests'][0]['status']=='EXPIRED'


@pytest.mark.parametrize('name,state,result,child,expected',[
    ('QUEUE_EXECUTION_FINISHED','SUCCEEDED','0','0','SUCCEEDED'),
    ('QUEUE_EXECUTION_FINISHED','SUCCEEDED','0','1','UNKNOWN'),
    ('QUEUE_EXECUTION_FINISHED','FAILED','14','1','FAILED'),
    ('QUEUE_DISPATCH_FAILED','FAILED','14',None,'FAILED'),
    ('VIEW_DENIED','DENIED',None,None,'DENIED'),
    ('QUEUE_BLOCKED','BLOCKED',None,None,'BLOCKED'),
    ('QUEUE_EXECUTION_OUTCOME_UNKNOWN','EXECUTION_UNKNOWN','16',None,'UNKNOWN'),
    ('PAM_AUTHENTICATION_FINISHED','SUCCEEDED',None,None,'UNKNOWN')])
def test_authority(name,state,result,child,expected):
    r=event(name,MAYI_STATE=state,MAYI_RESULT=result,MAYI_CHILD_EXIT_STATUS=child)
    assert doc([r])['requests'][0]['status']==expected


def test_conflicting_terminal_is_unknown():
    assert doc([done(),event('VIEW_DENIED')])['requests'][0]['status']=='UNKNOWN'


def test_separate_boots_instances_even_when_request_id_reused():
    d=doc([done(),done(_BOOT_ID='e'*32),done(MAYI_BROKER_INSTANCE_ID='f'*48)])
    assert len(d['requests'])==3


def test_explicit_bridges_only():
    root=dict(_SYSTEMD_UNIT='mayi-privileged-executor.service',_UID='0',MAYI_REQUEST_ID=None,
              MAYI_BROKER_INSTANCE_ID=None,MAYI_CHALLENGE_ID=None,MAYI_REQUEST_DIGEST=None,
              MAYI_EXECUTION_ID='1'*32,MAYI_STATE='SUCCEEDED',MAYI_CHILD_EXIT_STATUS='0')
    executor=event('EXECUTION_FINISHED',**root)
    assert len(doc([event(),executor])['requests'])==2  # no rq_ prefix inference
    mapped=doc([event(MAYI_EXECUTION_ID='1'*32),executor])['requests']
    assert len(mapped)==1 and mapped[0]['status']=='SUCCEEDED'
    ambiguous=doc([event(MAYI_EXECUTION_ID='1'*32),event(MAYI_EXECUTION_ID='1'*32,MAYI_BROKER_INSTANCE_ID='e'*48),executor])
    assert len(ambiguous['requests'])==3
    capped,omitted=h.reconstruct([event(MAYI_EXECUTION_ID='1'*32),event(MAYI_EXECUTION_ID='1'*32,MAYI_BROKER_INSTANCE_ID='e'*48),executor],1)
    assert len(capped[0]['events'])==1 and omitted==2


def test_pam_requires_exact_mapping():
    pam=event('PAM_ACCOUNT_CHECK_FINISHED', _SYSTEMD_UNIT='mayi-pam-auth.service',_UID='0',MAYI_REQUEST_ID=None)
    assert len(doc([event(),pam])['requests'])==1
    pam['request_digest']='e'*64
    assert len(doc([event(),pam])['requests'])==2


def test_missing_instance_does_not_merge_but_request_still_filterable():
    rows=[event(MAYI_BROKER_INSTANCE_ID=None), event(MAYI_BROKER_INSTANCE_ID=None,__REALTIME_TIMESTAMP='1792306800000001')]
    d=doc(rows,'--request','rq_'+'1'*32)
    assert len(d['requests'])==2 and all(r['correlation_incomplete'] for r in d['requests'])


@pytest.mark.parametrize('fields',[{'MAYI_EVENT':'BAD\nFAKE'}, {'MAYI_STATE':'OK\x1b'}, {'MAYI_RESULT':'Some(0)'},
    {'MAYI_RESULT':['0']},{'MAYI_REQUEST_ID':'rq_'+'a'*10000},{'_UID':'1000'}, {'_BOOT_ID':None},
    {'__REALTIME_TIMESTAMP':'9999999999999999999'}, {'MAYI_EVENT':None}, {'MAYI_CHALLENGE_ID':'bad'}])
def test_malformed(fields):
    assert h.decode(json.dumps(raw(**fields))) is None


def test_controls_and_sensitive_fields_never_displayed():
    r=raw(MESSAGE='\x1b[2J SECRET', MAYI_ARGV='SECRET', MAYI_REASON='PASSWORD', _CMDLINE='SECRET')
    encoded=json.dumps(doc([h.decode(json.dumps(r))]))
    assert 'SECRET' not in encoded and 'PASSWORD' not in encoded and '\x1b' not in h.render(doc([event()]),width=24)
    assert all(len(line)<=24 for line in h.render(doc([done()]),True,24).splitlines())
    assert 'rq_'+'1'*32 in h.render(doc([done()]),True,120)


def test_fixed_argv_since_not_shell():
    c=h.command('1 hour ago; touch /tmp/never')
    assert c[0]=='/usr/bin/journalctl' and '--since=1 hour ago; touch /tmp/never' in c
    assert '--system' in c and '--reverse' in c


@pytest.mark.parametrize('code,name',[(13,'JOURNAL_ACCESS_DENIED'),(15,'JOURNAL_UNAVAILABLE'),(15,'JOURNAL_READ_FAILED')])
def test_error_json(code,name,monkeypatch,capsys):
    def fail(since):raise h.HistoryError(code,name,'bounded error')
    monkeypatch.setattr(h,'read_journal',fail)
    assert h.main(['--json'])==code
    value=json.loads(capsys.readouterr().out);assert value['error']['code']==name


def test_empty_and_redirected(capsys,monkeypatch):
    monkeypatch.setattr(h,'read_journal',lambda since:([],dict(scanned_records=0,ignored_records=0,scan_truncated=False,bytes_read=0)))
    assert h.main([])==0
    out=capsys.readouterr().out
    assert 'No matching' in out and '\x1b' not in out


def test_bounded_synthetic_large_set():
    events=[done(MAYI_REQUEST_ID='rq_'+format(i,'032x')) for i in range(10000)]
    begin=time.monotonic();rows,omitted=h.reconstruct(events)
    assert len(rows)==h.MAX_GROUPS and omitted==8000
    assert time.monotonic()-begin<10


def test_transport_permission_and_malformed(monkeypatch):
    real=subprocess.Popen
    fixture=(json.dumps(raw())+'\nnot-json\n').encode()
    def spawn(argv,**kw):
        return real([sys.executable,'-c','import os;os.write(1,'+repr(fixture)+');os.write(2,b"No journal files were opened due to insufficient permissions.")'],**kw)
    monkeypatch.setattr(h.subprocess,'Popen',spawn)
    with pytest.raises(h.HistoryError) as exc:h.read_journal()
    assert exc.value.code==13


def test_transport_line_size_and_partial(monkeypatch):
    real=subprocess.Popen
    fixture=b'x'*(h.MAX_LINE+10)+b'\n'+json.dumps(raw()).encode()+b'\npartial'
    def spawn(argv,**kw):return real([sys.executable,'-c','import os;os.write(1,'+repr(fixture)+')'],**kw)
    monkeypatch.setattr(h.subprocess,'Popen',spawn)
    records,stats=h.read_journal()
    assert len(records)==1 and stats['ignored_records']==2
