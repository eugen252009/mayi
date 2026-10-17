import os, subprocess, time
from mayi.mutations import file_patch,file_create
import pytest
from mayi.executor import RustExecutorClient, RustApprovalAuthorityClient, ExecutorError

def test_filesystem_mutation_remains_disabled_after_proposal(tmp_path):
    root=tmp_path/'fake-root';target=root/'etc/config';target.parent.mkdir(parents=True);target.write_text('A')
    request=tmp_path/'request.sock';approval=tmp_path/'approval.sock'
    proc=subprocess.Popen(['executor/target/debug/mayi-executor','--request-socket',str(request),'--approval-socket',str(approval),'--request-gid',str(os.getgid()),'--approval-gid',str(os.getgid()),'--development-same-uid'])
    try:
        for _ in range(200):
            if request.exists():break
            time.sleep(.01)
        client=RustExecutorClient(socket_path=str(request))
        for op in (file_patch('/etc/config','A','B'),file_create('/etc/new','N')):
            with pytest.raises(ExecutorError, match='UNSUPPORTED_OPERATION'):
                client.submit([op])
        assert RustApprovalAuthorityClient(str(approval)).list_pending()['pending']==[]
        assert target.read_text()=='A' and not (root/'etc/new').exists()
    finally:
        proc.terminate();proc.wait(timeout=3)

def test_fake_root_dry_run_combination_is_rejected(tmp_path):
    root=tmp_path/'fake-root';root.mkdir();target=root/'new'
    p=subprocess.run(['executor/target/debug/mayi-executor','--dry-run','--fake-root',str(root)],input=b'{}',capture_output=True)
    assert p.returncode!=0 and not target.exists()
