import json, subprocess, time
import pytest
from pathlib import Path
from mayi.mutations import file_create
from mayi.protocol import request_document

def test_fake_root_execution_requires_independent_authority(tmp_path):
    root=tmp_path/'root';root.mkdir();doc=request_document([file_create('/new','x')])
    p=subprocess.run(['executor/target/debug/mayi-executor','--stdio'],input=json.dumps(doc),text=True,capture_output=True)
    assert json.loads(p.stdout)['code']=='APPROVAL_SOCKET_REQUIRED'
    assert not (root/'new').exists()

def test_traversal_rejected_by_operation_schema():
    with pytest.raises(ValueError): request_document([file_create('/etc/../outside','x')])
