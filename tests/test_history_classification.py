"""Public deterministic reproduction of three requests plus six diagnostics.
The operator's actual captured journal remains outside source in qualification evidence.
"""
import json
import pytest
from mayi import history as h
from test_history import raw, event, done, doc


def scenario():
    rows=[]
    def add(name,which='1',unit='mayi-broker.service',**fields):
        base=dict(MAYI_REQUEST_ID=None,MAYI_CHALLENGE_ID=which*48,MAYI_REQUEST_DIGEST=which*64,
                  _SYSTEMD_UNIT=unit,_UID='23002' if unit=='mayi-broker.service' else '0',
                  __REALTIME_TIMESTAMP=str(1792314000000000+len(rows)*1000000),
                  __MONOTONIC_TIMESTAMP=str(1000000+len(rows)*1000000),__CURSOR='cursor-'+str(len(rows)))
        if unit!='mayi-broker.service':base['MAYI_REQUESTER_UID']=None
        base.update(fields);r=h.decode(json.dumps(raw(name,**base)));assert r is not None;rows.append(r)
    add('PROPOSED');add('VIEW_CREATED')
    add('PAM_ACCOUNT_CHECK_FINISHED',unit='mayi-pam-auth.service',MAYI_STATE='SUCCEEDED')
    add('VIEW_APPROVED',MAYI_STATE='APPROVED');add('CONSUMED',MAYI_STATE='CONSUMED')
    add('EXECUTION_DISPATCH_STARTED',MAYI_EXECUTION_ID='a'*32,MAYI_STATE='CONSUMED')
    root=dict(MAYI_BROKER_INSTANCE_ID=None,MAYI_CHALLENGE_ID=None,MAYI_REQUEST_DIGEST=None,MAYI_EXECUTION_ID='a'*32)
    add('EXECUTION_STARTED',unit='mayi-privileged-executor.service',MAYI_STATE=None,**root)
    add('EXECUTION_FINISHED',unit='mayi-privileged-executor.service',MAYI_STATE='SUCCEEDED',MAYI_CHILD_EXIT_STATUS='0',**root)
    add('EXECUTION_FINISHED',MAYI_STATE='SUCCEEDED',MAYI_RESULT='0',MAYI_CHILD_EXIT_STATUS='0',MAYI_EXECUTION_ID='a'*32)
    for which in ['2','3']:
        add('PROPOSED',which);add('VIEW_CREATED',which);add('VIEW_REPLACED',which);add('VIEW_DENIED',which,MAYI_STATE='DENIED')
    for name in ['CONSOLE_SESSION_AUTHENTICATED','CONSOLE_SESSION_REVOKED','PAM_AUTHENTICATION_FINISHED']*2:
        add(name,unit='mayi-pam-auth.service' if name.startswith('PAM') else 'mayi-broker.service',
            MAYI_CHALLENGE_ID=None,MAYI_REQUEST_DIGEST=None,MAYI_REQUESTER_UID=None,MAYI_STATE='SUCCEEDED')
    assert len(rows)==23
    return list(reversed(rows))


def test_three_requests_six_system_events_do_not_become_fake_requests():
    records=scenario();d=doc(records)
    assert d['schema_version']==2 and d['mode']=='requests' and d['count_unit']=='requests'
    assert d['matched']==d['returned']==3 and d['diagnostic_records']==6
    assert d['ignored_records']==d['omitted_records']==0
    assert [r['identity'] for r in d['requests']]==['ch_'+'3'*48,'ch_'+'2'*48,'ch_'+'1'*48]
    assert [r['status'] for r in d['requests']]==['DENIED','DENIED','SUCCEEDED']
    successful=d['requests'][-1]
    assert successful['exit_code']==0 and len(successful['events'])==9
    assert not successful['correlation_incomplete'] and successful['request_id'] is None
    text=h.render(d);assert 'event_' not in text and 'PAM_AUTHENTICAT' not in text and 'matched requests' in text


def test_events_include_every_valid_record_without_fake_identities():
    d=doc(scenario(),'--events','--all')
    assert d['requests']==[] and d['mode']=='events' and d['count_unit']=='events'
    assert d['matched']==d['returned']==len(d['events'])==23
    assert len([e for e in d['events'] if e['request_identity'] is None])==6
    assert [e['timestamp'] for e in d['events']]==sorted(e['timestamp'] for e in d['events'])
    text=h.render(d);assert 'Audit Events' in text and 'CONSOLE_SESSION' in text and 'event_' not in text
    assert h.safe('not\x1b[2J\n',100)=='not\\x1b[2J\\n'


def test_challenge_detail_keeps_executor_bridge_and_pam_account_only():
    d=doc(scenario(),'--request','ch_'+'1'*48)
    assert len(d['requests'])==1
    names={e['event'] for e in d['requests'][0]['events']}
    assert {'PROPOSED','CONSUMED','EXECUTION_DISPATCH_STARTED','PAM_ACCOUNT_CHECK_FINISHED','EXECUTION_STARTED','EXECUTION_FINISHED'}<=names
    assert 'PAM_AUTHENTICATION_FINISHED' not in names
    detail=h.render(d,True);assert 'ch_'+'1'*48 in detail and 'EXECUTION_STARTED' in detail
    ev=doc(scenario(),'--events','--request','ch_'+'1'*48,'--all')
    assert len(ev['events'])==9 and all(e['request_identity']=='ch_'+'1'*48 for e in ev['events'])


def test_limits_apply_to_correct_objects_and_filters_to_request_outcomes():
    records=scenario()
    assert doc(records,'--limit','2')['returned']==2
    assert doc(records,'--events','--limit','2')['returned']==2
    assert all(e['request_identity'] is None for e in doc(records,'--events','--limit','2')['events'])
    assert doc(records,'--status','denied')['matched']==2
    assert doc(records,'--status','success')['matched']==1
    assert doc(records,'--events','--status','denied','--all')['matched']==8
    many=records+list(records[:6])*100
    assert doc(many)['returned']==3  # diagnostics do not consume request cap/limit


@pytest.mark.parametrize('name',['CONSOLE_SESSION_AUTHENTICATED','CONSOLE_SESSION_REVOKED','PAM_AUTHENTICATION_FINISHED','EXECUTOR_READY','REQUEST_REJECTED'])
def test_strings_that_look_like_request_ids_are_not_lifecycle_evidence(name):
    # Even forged valid-looking broker fields do not make a session/error a request.
    row=event(name,MAYI_STATE='SUCCEEDED',MAYI_CHILD_EXIT_STATUS='0')
    assert doc([row])['requests']==[]
    d=doc([row],'--events');assert d['matched']==1 and d['events'][0]['request_identity'] is None


@pytest.mark.parametrize('field',['broker_instance_id','challenge_id','request_digest','requester_uid'])
def test_missing_identity_proof_is_diagnostic_not_discarded(field):
    row=event();row[field]=None
    assert not doc([row])['requests']
    assert doc([row],'--events')['matched']==1


def test_retention_without_proposal_and_unknown_without_execution():
    assert doc([event('VIEW_DENIED')])['requests'][0]['status']=='DENIED'
    for name in ['PROPOSED','VIEW_APPROVED','CONSUMED']:
        r=event(name)
        d=doc([r]);assert d['requests'][0]['status']=='UNKNOWN'
        assert 'UNKNOWN' in h.render(d) and 'not a live pending request' in h.render(d)
    # Only a helper completion without an authoritative broker binding is a diagnostic.
    root=event('EXECUTION_FINISHED',_SYSTEMD_UNIT='mayi-privileged-executor.service',_UID='0',MAYI_STATE='SUCCEEDED',MAYI_CHILD_EXIT_STATUS='0')
    assert not doc([root])['requests'] and doc([root],'--events')['matched']==1


def test_boot_instance_binding_and_conflicting_identities_never_merge():
    rows=[done(),done(_BOOT_ID='e'*32),done(MAYI_BROKER_INSTANCE_ID='f'*48),done(MAYI_REQUEST_DIGEST='e'*64)]
    d=doc(rows);assert len(d['requests'])==4
    assert len({(r['boot_id'],r['broker_instance_id'],r['identity'],r['request_digest']) for r in d['requests']})==4


def test_same_queue_binding_is_not_a_duplicate_challenge_request():
    p=event();v=event('VIEW_CREATED',MAYI_REQUEST_ID=None)
    d=doc([p,v]);assert len(d['requests'])==1 and len(d['requests'][0]['events'])==2


def test_events_resource_cap_does_not_hide_diagnostics_in_request_cap():
    rows=[done(MAYI_REQUEST_ID='rq_'+format(i,'032x')) for i in range(h.MAX_GROUPS+1)]
    rows.append(event('CONSOLE_SESSION_REVOKED',MAYI_REQUEST_ID=None))
    d=doc(rows,'--events','--all')
    assert d['matched']==h.MAX_GROUPS+2 and d['omitted_records']==1
    assert doc(rows,'--all')['matched']==h.MAX_GROUPS


def test_empty_duplicate_malformed_json_and_controls(monkeypatch,capsys):
    records=scenario();assert doc(records*2)['matched']==3
    assert doc(records*2,'--events','--all')['matched']==23
    monkeypatch.setattr(h,'read_journal',lambda since:([],dict(scanned_records=0,ignored_records=0,scan_truncated=False,bytes_read=0)))
    assert h.main(['--events','--json'])==0
    d=json.loads(capsys.readouterr().out);assert d['schema_version']==2 and d['events']==d['requests']==[]
    assert h.decode(b'{bad') is None
    assert h.decode(json.dumps(raw(MAYI_EVENT='CONSOLE\nFAKE'))) is None
