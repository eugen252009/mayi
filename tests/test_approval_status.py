import errno
import io
import json
import pytest
from mayi import approval_status as s
from mayi.executor import ExecutorError


def snapshot(**kw):
    v=dict(ok=True,protocol=5,response_to='QUEUE_STATUS',schema_version=1,broker='ONLINE',
        broker_instance_id='a'*48,snapshot_unix_ms=1792306800000,scope='approver_global_aggregate',
        total_active=0,blocked_terminal=0,outcome_unknown_terminal=0,**{k:0 for k in s.COUNTERS})
    v.update(kw);return v


def test_schema_numeric_exclusive_no_console_claim():
    v=snapshot(pending_approval=2,waiting_dependency=3,dispatching=1,running=1,total_active=7)
    assert s.validate(v)==v
    p=s.public(v);assert p['total_active']==7 and p['snapshot_time'].endswith('+00:00')
    assert 'console' not in p


@pytest.mark.parametrize('kw',[{'total_active':1},{'running':-1},{'running':True},{'running':'0'},
    {'pending_approval':137,'total_active':137},{'pending_approval':136,'total_active':136,'blocked_terminal':1},
    {'broker_instance_id':'\x1b'*48},{'snapshot_unix_ms':True},{'snapshot_unix_ms':-1},{'schema_version':True},
    {'extra':'secret'},{'scope':'all secrets'},{'protocol':True},{'response_to':'LIST_PENDING'}])
def test_malformed(kw):
    with pytest.raises(ExecutorError):s.validate(snapshot(**kw))


@pytest.mark.parametrize('args',[['--interval','0'],['--watch','--interval','.1'],['--watch','--interval','61'],
    ['--watch','--interval','nan'],['--watch','--interval','inf'],['--bad']])
def test_invalid(args,capsys):
    assert s.main(args+['--json'])==12
    p=json.loads(capsys.readouterr().out);assert 'total_active' not in p


def test_oneshot_and_redirected(capsys,monkeypatch):
    monkeypatch.setattr(s,'fetch',lambda:snapshot())
    assert s.main([])==0;out=capsys.readouterr().out
    assert 'Approval Status' in out and '\x1b' not in out
    assert s.main(['--json'])==0;v=json.loads(capsys.readouterr().out)
    assert v['total_active']==0 and type(v['running']) is int


def test_offline_not_zero(capsys,monkeypatch):
    def no():raise s.StatusError(15,'OFFLINE','unavailable')
    monkeypatch.setattr(s,'fetch',no)
    assert s.main(['--json'])==15
    p=json.loads(capsys.readouterr().out);assert p['broker']=='OFFLINE' and 'running' not in p


@pytest.mark.parametrize('exc,code,health',[(PermissionError(),13,'UNAVAILABLE'),
    (FileNotFoundError(errno.ENOENT,'missing'),15,'OFFLINE'),
    (ConnectionRefusedError(errno.ECONNREFUSED,'refused'),15,'OFFLINE'),
    (TimeoutError(),15,'UNAVAILABLE'),(ExecutorError('UNAUTHORIZED_APPROVER'),13,'UNAVAILABLE'),
    (ExecutorError('invalid'),15,'UNAVAILABLE')])
def test_transport_error_mapping(exc,code,health,monkeypatch):
    class Client:
        def __init__(self,*a,**k):pass
        def _call(self,msg):assert msg=={'type':'QUEUE_STATUS'};raise exc
    monkeypatch.setattr(s,'RustApprovalAuthorityClient',Client)
    with pytest.raises(s.StatusError) as e:s.fetch()
    assert (e.value.code,e.value.broker)==(code,health)


def test_pipe_watch_requires_json(capsys):
    assert s.main(['--watch'])==12
    assert '\x1b' not in capsys.readouterr().out


def test_json_watch_recovery_and_cancel(capsys,monkeypatch):
    calls=[]
    def get():
        calls.append(1)
        if len(calls)==1:raise s.StatusError(15,'OFFLINE','unavailable')
        if len(calls)==3:raise KeyboardInterrupt
        return snapshot(pending_approval=2,total_active=2)
    monkeypatch.setattr(s,'fetch',get);monkeypatch.setattr(s.time,'sleep',lambda n:None)
    assert s.main(['--watch','--json','--interval','.5'])==130
    lines=[json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert lines[0]['broker']=='OFFLINE' and 'total_active' not in lines[0]
    assert lines[1]['pending_approval']==2


def test_tty_watch_resize_and_cleanup(monkeypatch):
    class TTY(io.StringIO):
        def isatty(self):return True
    out=TTY();monkeypatch.setattr(s.sys,'stdout',out);monkeypatch.setenv('TERM','xterm')
    calls=[]
    def get():
        calls.append(1)
        if len(calls)>2:raise KeyboardInterrupt
        return snapshot(pending_approval=len(calls),total_active=len(calls))
    monkeypatch.setattr(s,'fetch',get);monkeypatch.setattr(s.time,'sleep',lambda n:None)
    assert s.main(['--watch'])==130
    assert out.getvalue().endswith('\x1b[?25h\x1b[?1049l')
    assert all(len(line)<=20 for line in s.render(s.public(snapshot()),width=20).splitlines())
