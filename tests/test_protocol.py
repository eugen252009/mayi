import json
from mayi.operations import Operation,Kind
from mayi.protocol import digest,request_document,canonical_bytes,PROTOCOL_VERSION
from mayi.executor import DryRunExecutor

def test_integrity_digest_is_stable_but_not_authorization():
    a=[Operation(Kind.FILE_WRITE,'/etc/foo')]
    fields=dict(requester_uid=1000,target_uid=1000,target_gid=1000)
    assert digest(a,**fields)==digest(a,**fields)
    assert digest(a,**fields)!=digest([Operation(Kind.FILE_WRITE,'/etc/bar')],**fields)
    assert digest(a,**fields)!=digest(a,**{**fields,'target_uid':1001})

def test_v5_proposal_contains_no_client_authority_fields():
    ops=[Operation(Kind.FILE_CREATE,'/tmp/a',content='x')]
    doc=request_document(ops)
    assert doc['protocol']==5 and doc['type']=='PROPOSE_REQUEST'
    assert set(doc)=={'type','protocol','target','operations'}
    assert not {'approval','approved','decision','scope','challenge_id'} & doc.keys()
    assert DryRunExecutor().submit(ops)['validation_only'] is True

def test_legacy_authorization_fields_are_rejected():
    with __import__('pytest').raises(ValueError): request_document([Operation(Kind.FILE_WRITE,'/tmp/a')],approval_digest='a'*64)

def test_canonical_material_binds_operation_identity():
    data=json.loads(canonical_bytes([Operation(Kind.FILE_READ,'/tmp/space name')],target_uid=1000,target_gid=1000))
    assert data['protocol']==PROTOCOL_VERSION and data['target_uid']==1000
