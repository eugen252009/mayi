import copy,io,json,os,pty,signal,subprocess,sys,termios,fcntl,struct,select,time
import pytest
from mayi import approval_status as s,history as h,cli
from mayi.progress import Waiting
from test_approval_status import snapshot
from test_history import done,event,doc
SIZES=[(120,40),(100,30),(80,24),(60,20),(40,12),(30,8)]

@pytest.mark.parametrize('size',SIZES)
def test_compact_status_fits_and_details_preserve_all_counters(size):
    width,height=size
    v=snapshot(pending_approval=3,waiting_dependency=1,running=2,total_active=6,blocked_terminal=1,outcome_unknown_terminal=1)
    before=copy.deepcopy(v);text=s.render(s.public(v),width=width,height=height)
    assert len(text.splitlines())<=height and max(map(len,text.splitlines()))<width
    assert '3 waiting' in text and '2 running' in text and 'Unknown 1' in text and 'Blocked 1' in text and '6 active' in text
    detail=s.render(s.public(v),width=120,details=True)
    for label in ['Pending approval','Waiting on dependencies','Approved / ready','Awaiting requester consume','Dispatching / unconfirmed start','Running (observed start)','Total active requests']:assert label in detail
    assert v==before


def test_empty_unknown_and_json_no_style_semantics_change(capsys,monkeypatch):
    v=snapshot();monkeypatch.setattr(s,'fetch',lambda:v)
    assert s.main([])==0;text=capsys.readouterr().out
    assert 'No pending approvals.' in text and 'No active requests.' in text
    assert s.main(['--details','--json'])==0;assert json.loads(capsys.readouterr().out)==s.public(v)
    v['outcome_unknown_terminal']=1
    assert 'Unknown 1' in s.render(s.public(v))
    result,exitcode=s.preflight(s.public(v));assert result['preflight']=='UNKNOWN' and exitcode==4


def test_plain_watch_never_emits_ansi_or_requires_tty(monkeypatch,capsys):
    monkeypatch.setenv('TERM','dumb');calls=[]
    def get():
        calls.append(1)
        if len(calls)>2:raise KeyboardInterrupt
        return snapshot(pending_approval=len(calls),total_active=len(calls))
    monkeypatch.setattr(s,'fetch',get);monkeypatch.setattr(s.time,'sleep',lambda _:None)
    assert s.main(['--watch','--plain','--interval','.5'])==130
    out=capsys.readouterr().out;assert '\x1b' not in out and out.count('Snapshot 20')==2 and '1 waiting' in out and '2 waiting' in out
    assert s.main(['--watch'])==12 and '--plain' in capsys.readouterr().err

@pytest.mark.parametrize('args',[['--plain'],['--watch','--plain','--json']])
def test_invalid_plain_combination(args,capsys):
    assert s.main(args)==12 and '\x1b' not in capsys.readouterr().out

@pytest.mark.parametrize('size',SIZES)
def test_actual_stderr_pty_spinner_width_and_modes(monkeypatch,size):
    monkeypatch.setenv('TERM','xterm');master,slave=pty.openpty();width,height=size
    try:
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',height,width,0,0));before=termios.tcgetattr(slave)
        with os.fdopen(os.dup(slave),'w') as stream:
            with Waiting(stream,lambda:12.0) as waiting:waiting.tick()
        raw=os.read(master,4096).decode();text=raw.removeprefix('\r\x1b[2K').removesuffix('\r\x1b[2K')
        assert 'Waiting' in text and len(text)<width and '\n' not in text and termios.tcgetattr(slave)==before
    finally:os.close(master);os.close(slave)

@pytest.mark.parametrize('size',SIZES)
def test_real_pty_watch_interrupt_resize_cleanup(size):
    width,height=size;master,slave=pty.openpty();before=termios.tcgetattr(slave)
    fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',height,width,0,0))
    code="from mayi import approval_status as s; s.fetch=lambda:"+repr(snapshot(pending_approval=3,waiting_dependency=1,running=2,total_active=6))+"; raise SystemExit(s.main(['--watch','--interval','.5']))"
    p=subprocess.Popen([sys.executable,'-c',code],stdin=slave,stdout=slave,stderr=slave,env={**os.environ,'TERM':'xterm','COLUMNS':'999','LINES':'999'},start_new_session=True)
    out=b''
    try:
        until=time.monotonic()+5
        while b'6 active requests' not in out:
            assert time.monotonic()<until,out
            if select.select([master],[],[],.1)[0]:out+=os.read(master,65536)
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',8,30,0,0));time.sleep(.6)
        p.send_signal(signal.SIGINT);p.wait(timeout=5)
        while select.select([master],[],[],.05)[0]:out+=os.read(master,65536)
        assert p.returncode==130 and b'\x1b[?1049l' in out and b'\x1b[?25h' in out
        assert termios.tcgetattr(slave)==before and b'Password:' not in out
        for frame in out.split(b'\x1b[H\x1b[J')[1:]:
            frame=frame.split(b'\x1b[?25h')[0];assert len(frame.splitlines())<=height
    finally:
        if p.poll() is None:p.kill();p.wait()
        os.close(master);os.close(slave)


def test_v2_history_aliases_distinct_without_rewriting_records():
    rows=[]
    for i in range(3):rows.append(done(MAYI_REQUEST_ID='rq_v2_'+'b'*48+'_'+str(i)*32+'_'+'d'*64+'_'+'e'*64))
    d=doc(rows,'--all');before=copy.deepcopy(d)
    for width,height in SIZES:
        text=h.render(d,width=width)
        for i in range(3):assert 'rq:'+str(i)*12 in text
        assert max(map(len,text.splitlines()))<=max(24,width)
    assert d==before and len(set(r['identity'] for r in d['requests']))==3
    unknown=doc([event()]);assert 'UNKNOWN' in h.render(unknown) and 'PENDING?' not in h.render(unknown)
    assert 'MAYI/EXIT' in h.render(d)


def test_safe_broker_guidance_preserves_code(capsys):
    assert cli._mayi_error('MAYI_BROKER_ERROR: unavailable',15)==15
    out=capsys.readouterr();assert not out.out and 'MAYI_BROKER_ERROR' in out.err and 'Reconcile' in out.err
    assert cli._mayi_error('MAYI_EXECUTION_UNKNOWN',16)==16
    assert 'do not automatically retry' in capsys.readouterr().err
