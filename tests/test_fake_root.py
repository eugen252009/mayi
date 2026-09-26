import os, subprocess, time
from mayi.mutations import file_patch,file_create
from mayi.executor import RustExecutorClient

def test_filesystem_mutation_remains_disabled_after_proposal(tmp_path):
    root=tmp_path/'fake-root';target=root/'etc/config';target.parent.mkdir(parents=True);target.write_text('A')
    request=tmp_path/'request.sock';approval=tmp_path/'approval.sock'
    proc=subprocess.Popen(['executor/target/debug/mayi-executor','--request-socket',str(request),'--approval-socket',str(approval),'--request-uid',str(os.getuid()),'--request-gid',str(os.getgid()),'--approval-uid',str(os.getuid()+1),'--approval-gid',str(os.getgid()),'--development-same-uid'])
    try:
        for _ in range(200):
            if request.exists():break
            time.sleep(.01)
        client=RustExecutorClient(socket_path=str(request))
        for op in (file_patch('/etc/config','A','B'),file_create('/etc/new','N')):
            response=client.submit([op]);assert response['status']=='PENDING_APPROVAL'
        assert target.read_text()=='A' and not (root/'etc/new').exists()
    finally:
        proc.terminate();proc.wait(timeout=3)

def test_fake_root_dry_run_combination_is_rejected(tmp_path):
    root=tmp_path/'fake-root';root.mkdir();target=root/'new'
    p=subprocess.run(['executor/target/debug/mayi-executor','--dry-run','--fake-root',str(root)],input=b'{}',capture_output=True)
    assert p.returncode!=0 and not target.exists()
