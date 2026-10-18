import copy,json
import pytest
from mayi import history as h,approval_status as s,executor as e,cli
from mayi.request_ids import valid_request_id,encoded_epoch
from test_history import event,done,doc
from test_approval_status import snapshot

A='b'*48; B='e'*48
ID='rq_v2_'+A+'_'+'1'*32+'_'+'d'*64+'_'+'2'*64

def lifecycle(name,epoch,order):
    return event(name,MAYI_REQUEST_ID=None,MAYI_CHALLENGE_ID=None,MAYI_REQUEST_DIGEST=None,MAYI_BROKER_INSTANCE_ID=epoch,__MONOTONIC_TIMESTAMP=str(order))

def test_virtual_boundaries_preserve_order_and_filtering():
    rows=[done(MAYI_BROKER_INSTANCE_ID=A,__MONOTONIC_TIMESTAMP='1000000'),done(MAYI_REQUEST_ID='rq_'+'2'*32,MAYI_BROKER_INSTANCE_ID=B,__MONOTONIC_TIMESTAMP='2000000',__REALTIME_TIMESTAMP='1792306801000000'),done(MAYI_REQUEST_ID='rq_'+'3'*32,MAYI_BROKER_INSTANCE_ID=B,__MONOTONIC_TIMESTAMP='3000000',__REALTIME_TIMESTAMP='1792306802000000')]
    original=copy.deepcopy(rows);d=doc(rows,'--all');text=h.render(d)
    assert text.count('--- NEW EPOCH ---')==1 and rows==original
    assert [r['epoch_id'] for r in d['requests']]==[B,B,A]
    one=doc(rows,'--limit','1');assert 'Epoch: '+B[:12] in h.render(one) and 'NEW EPOCH' not in h.render(one)
    assert len(doc(rows,'--limit','2')['requests'])==2
    assert doc(rows,'--epoch',A)['returned']==1
    assert doc(rows,'--request','rq_'+'2'*32,'--epoch',B)['returned']==1
    assert doc(rows,'--request','rq_'+'2'*32,'--epoch',A)['returned']==0

def test_events_legacy_epoch_is_never_fabricated():
    rows=[event(),event('PAM_AUTH_BEGIN',_SYSTEMD_UNIT='mayi-pam-auth.service',_UID='0',MAYI_BROKER_INSTANCE_ID=None),event('APPROVED',__MONOTONIC_TIMESTAMP='3000000')]
    d=doc(rows,'--events','--all');assert d['events'][1]['epoch_id'] is None
    assert 'UNKNOWN (legacy/unassociated)' in h.render(d)
    assert rows[1]['broker_instance_id'] is None

def test_restart_is_inference_not_safe_to_retry_and_completed_stays_completed():
    start=lifecycle('BROKER_STARTED',B,2000000)
    for record,status in [(event(),'UNKNOWN'),(done(),'SUCCEEDED')]:
        r=doc([record,start])['requests'][0]
        assert r['authorization_state']=='INVALIDATED' and r['invalidation_reason']=='BROKER_RESTARTED'
        assert r['invalidation_evidence']=='EPOCH_LIFECYCLE_INFERENCE' and r['status']==status
        assert r['recovery_classification']==('COMPLETED' if status=='SUCCEEDED' else 'RECONCILIATION_REQUIRED')
    unknown=doc([event(),start])['requests'][0]
    assert unknown['execution_outcome']=='UNKNOWN'

def test_explicit_fence_is_distinct_from_unknown_execution():
    fenced=event('REQUEST_INVALIDATED',MAYI_STATE='INVALIDATED',MAYI_REASON='BROKER_STOPPING',__MONOTONIC_TIMESTAMP='2000000')
    r=doc([event(),fenced])['requests'][0]
    assert r['recovery_classification']=='SAFE_TO_RECREATE_REQUEST' and r['execution_outcome']=='NOT_DISPATCHED'
    assert 'INVALIDATED' in h.render(doc([event(),fenced]))
    assert doc([event(),fenced],'--status','INVALIDATED')['returned']==1
    claimed=event('CONSUMED',MAYI_STATE='CONSUMED')
    assert doc([event(),fenced,claimed])['requests'][0]['recovery_classification']=='RECONCILIATION_REQUIRED'
    assert doc([event(),lifecycle('BROKER_STOPPING',A,2000000)])['requests'][0]['recovery_classification']=='RECONCILIATION_REQUIRED'

def test_v2_history_retains_legacy_and_new_ids_without_authenticating():
    assert valid_request_id(ID) and encoded_epoch(ID)==A
    r=doc([done(MAYI_REQUEST_ID=ID)],'--request',ID)['requests'][0]
    assert r['request_id']==ID and r['epoch_id']==A
    assert valid_request_id('rq_'+'a'*32)
    for bad in [ID.upper(),ID+'0',ID.replace('v2','v3'),'rq_x']:
        assert not valid_request_id(bad)

def test_executor_bridge_cannot_cross_encoded_audit_epoch():
    broker=event('EXECUTION_DISPATCH_STARTED',MAYI_EXECUTION_ID='1'*32)
    root=event('EXECUTION_FINISHED',_SYSTEMD_UNIT='mayi-privileged-executor.service',_UID='0',MAYI_BROKER_INSTANCE_ID=B,MAYI_REQUEST_ID=None,MAYI_CHALLENGE_ID=None,MAYI_REQUEST_DIGEST=None,MAYI_EXECUTION_ID='1'*32,MAYI_STATE='SUCCEEDED',MAYI_CHILD_EXIT_STATUS='0')
    d=doc([broker,root],'--events','--all');assert d['events'][1]['request_identity'] is None

@pytest.mark.parametrize('counts,outcome,exitcode',[({},'READY',0),({'running':1,'total_active':1},'BUSY',3),({'outcome_unknown_terminal':1},'UNKNOWN',4),({'running':1,'total_active':1,'outcome_unknown_terminal':1},'BUSY',3)])
def test_preflight_read_only(monkeypatch,capsys,counts,outcome,exitcode):
    value=snapshot(**counts);before=copy.deepcopy(value);monkeypatch.setattr(s,'fetch',lambda:value)
    assert s.main(['--preflight','--json'])==exitcode
    d=json.loads(capsys.readouterr().out);assert d['preflight']==outcome and not d['admission_fenced'] and not d['physical_processes_verified'] and value==before

def test_preflight_errors_unknown_not_empty_ready(monkeypatch,capsys):
    def fail():raise s.StatusError(13,'UNAVAILABLE','permission denied')
    monkeypatch.setattr(s,'fetch',fail);assert s.main(['--preflight','--json'])==4
    d=json.loads(capsys.readouterr().out);assert d['preflight']=='UNKNOWN' and 'total_active' not in d
    assert s.main(['--watch','--preflight','--json'])==12

def mismatch():
    return dict(ok=False,protocol=5,response_to='GET_QUEUE_STATUS',code='BROKER_EPOCH_CHANGED',request_id=ID,epoch_id=A,broker_instance_id=B,error=dict(code='BROKER_EPOCH_CHANGED',request_id=ID,retryable=False,requires_new_request=True,requires_new_approval=True))

def test_authenticated_epoch_error_cli_and_json_never_retries(monkeypatch,capsys):
    calls=[]
    def exchange(*args,**kw):calls.append(args);return mismatch()
    monkeypatch.setattr(e,'_exchange',exchange)
    assert cli.main(['--status',ID])==16 and 'BROKER_EPOCH_CHANGED' in capsys.readouterr().err
    assert cli.main(['--status','--json',ID])==16
    result=json.loads(capsys.readouterr().out);assert result['error']['retryable'] is False and result['code']=='BROKER_EPOCH_CHANGED'
    assert len(calls)==2 and all(x[1]['type']=='GET_QUEUE_STATUS' for x in calls)

def test_unproven_mismatch_or_forged_response_is_not_authenticated_epoch(monkeypatch):
    monkeypatch.setattr(e,'_exchange',lambda *a,**kw:dict(ok=False,protocol=5,response_to='GET_QUEUE_STATUS',code='REQUEST_NOT_FOUND',message='unknown'))
    with pytest.raises(e.ExecutorError,match='REQUEST_NOT_FOUND'):e.RustExecutorClient(socket_path='unused').queue_status(ID)
    v=mismatch();v['request_id']='rq_'+'a'*32
    with pytest.raises(e.ExecutorError,match='invalid authenticated'):e._check_epoch(v,None,ID)
