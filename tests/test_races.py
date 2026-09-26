"""Fail-closed regression: until approval is independently authenticated, no
filesystem operation may enter the mutation path (race hooks are disabled).
"""
import os, subprocess, time
from mayi.executor import RustExecutorClient
from pathlib import Path
from mayi.mutations import file_patch,file_create,file_delete,file_move
from mayi.protocol import request_document

def test_all_mutation_types_blocked_without_authority(tmp_path):
    root=tmp_path/'root'; (root/'etc').mkdir(parents=True);(root/'etc/a').write_text('A')
    sock=tmp_path/'request.sock';auth=tmp_path/'approval.sock';p=subprocess.Popen(['executor/target/debug/mayi-executor','--request-socket',str(sock),'--approval-socket',str(auth),'--request-uid',str(os.getuid()),'--request-gid',str(os.getgid()),'--approval-uid',str(os.getuid()+1),'--approval-gid',str(os.getgid()),'--development-same-uid'])
    try:
        for _ in range(200):
            if sock.exists():break
            time.sleep(.01)
        ops=[file_patch('/etc/a','A','B'),file_create('/etc/new','N'),file_delete('/etc/a','A'),file_move('/etc/a','/etc/b','A')]
        for i,op in enumerate(ops):
            r=RustExecutorClient(socket_path=str(sock)).submit([op])
            assert r['status']=='PENDING_APPROVAL' and r['protocol']==5
        assert (root/'etc/a').read_text()=='A' and not (root/'etc/new').exists() and not (root/'etc/b').exists()
    finally:p.terminate();p.wait(timeout=3)
