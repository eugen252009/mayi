import hashlib
import pytest
from mayi.mutations import file_patch,file_create,file_delete,file_move,unified_diff
from mayi.operations import Kind
from mayi.protocol import canonical_operations,digest

def fields(op):
    return canonical_operations([op])[0]
def test_file_patch_binds_base_patch_and_result():
    op=file_patch('/etc/app.conf','enabled=false\n','enabled=true\n')
    p=fields(op)
    assert op.kind is Kind.FILE_PATCH
    assert p['expected_base_sha256']==hashlib.sha256(b'enabled=false\n').hexdigest()
    assert p['expected_result_sha256']==hashlib.sha256(b'enabled=true\n').hexdigest()
    common=dict(request_id='r',nonce='0123456789abcdef',requester_uid=1,expires_at=2000000000,target_uid=1,target_gid=1)
    assert digest([op],**common)!=digest([file_patch('/etc/app.conf','enabled=false\n','enabled=maybe\n')],**common)

def test_create_delete_move_are_explicit():
    assert fields(file_create('/tmp/a','x'))['type']=='file_create'
    assert fields(file_delete('/tmp/a','x'))['type']=='file_delete'
    assert fields(file_move('/tmp/a','/tmp/b','x'))['type']=='file_move'

def test_empty_base_uses_create():
    with pytest.raises(ValueError): file_patch('/tmp/a','','x')

def test_human_diff():
    assert '-enabled=false' in unified_diff('/etc/a','enabled=false\n','enabled=true\n')
