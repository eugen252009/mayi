import hashlib,json,subprocess
from pathlib import Path
from mayi.mutations import file_patch,file_create,file_delete,file_move
from mayi.protocol import request_document
from mayi.operations import Operation,Kind

def tree_digest(root):
    h=hashlib.sha256()
    for p in sorted(root.rglob('*')):
        rel=str(p.relative_to(root)).encode();h.update(rel)
        if p.is_file():h.update(p.read_bytes())
        elif p.is_symlink():h.update(str(p.readlink()).encode())
        h.update(str(p.stat(follow_symlinks=False).st_mode).encode())
    return h.hexdigest()

def test_stdio_validation_never_mutates_fixture(tmp_path):
    root=tmp_path/'fake-root';(root/'etc').mkdir(parents=True);(root/'etc/config').write_text('A')
    before=tree_digest(root)
    ops=[file_patch('/etc/config','A','B'),file_create('/etc/new','X'),file_delete('/etc/config','A'),file_move('/etc/config','/etc/moved','A')]
    for i,op in enumerate(ops):
        doc=request_document([op])
        p=subprocess.run(['executor/target/debug/mayi-executor','--stdio'],input=json.dumps(doc),text=True,capture_output=True,check=True)
        assert json.loads(p.stdout)['code']=='APPROVAL_SOCKET_REQUIRED'
    assert tree_digest(root)==before

def test_exec_and_service_are_rejected_by_executor_schema(tmp_path):
    for op in (Operation(Kind.EXEC,'/bin/echo',('x',)),Operation(Kind.SERVICE_RESTART,'example.service')):
        doc=request_document([op])
        p=subprocess.run(['executor/target/debug/mayi-executor','--stdio'],input=json.dumps(doc),text=True,capture_output=True,check=True)
        assert json.loads(p.stdout)['code']=='APPROVAL_SOCKET_REQUIRED'

def test_protocol5_broker_hands_only_stored_exec_to_privileged_boundary():
    broker=Path('executor/src/broker.rs').read_text()
    assert 'ExecutionContext' not in broker
    assert 'filesystem::' not in broker
    assert 'call_privileged_executor(&challenge, &operation)' in broker
    assert 'PRIVILEGED_EXECUTOR_SOCKET' in broker
    assert 'r["execution"] = Value::String("EXECUTION_DISABLED".into())' in broker
