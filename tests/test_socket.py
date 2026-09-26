import os, socket, stat, subprocess, time
from pathlib import Path
import pytest
from mayi.executor import RustExecutorClient, RustApprovalAuthorityClient, ExecutorError
from mayi.operations import Operation, Kind
from mayi.mutations import file_create

@pytest.fixture
def executor_binary():
    value=os.environ.get('MAYI_EXECUTOR_BIN','executor/target/debug/mayi-executor')
    if not Path(value).exists(): pytest.skip('build mayi-executor first')
    return value

def wait_socket(path):
    for _ in range(100):
        if path.exists(): return
        time.sleep(.01)
    raise AssertionError('executor socket did not appear')

def test_socket_peer_identity_and_framed_request(tmp_path, executor_binary):
    sock=tmp_path/'request.sock'; auth=tmp_path/'approval.sock'
    approver=os.getuid()+1
    p=subprocess.Popen([executor_binary,'--request-socket',str(sock),'--approval-socket',str(auth),'--request-uid',str(os.getuid()),'--request-gid',str(os.getgid()),'--approval-uid',str(approver),'--approval-gid',str(os.getgid()),'--development-same-uid'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        wait_socket(sock);wait_socket(auth)
        assert stat.S_IMODE(sock.stat().st_mode)==0o660 and sock.stat().st_gid==os.getgid()
        assert stat.S_IMODE(auth.stat().st_mode)==0o660 and auth.stat().st_gid==os.getgid()
        result=RustExecutorClient(socket_path=str(sock)).submit([file_create('/tmp/socket','x')])
        assert result['ok'] and result['status']=='PENDING_APPROVAL'
        with pytest.raises(ExecutorError,match='UNAUTHORIZED_APPROVER'):
            RustApprovalAuthorityClient(str(auth)).list_pending()
    finally:
        p.terminate(); p.wait(timeout=3)

def test_socket_path_regular_file_is_not_removed(tmp_path, executor_binary):
    sock=tmp_path/'request.sock'; auth=tmp_path/'approval.sock';sock.write_text('keep')
    p=subprocess.run([executor_binary,'--request-socket',str(sock),'--approval-socket',str(auth),'--request-uid',str(os.getuid()),'--request-gid',str(os.getgid()),'--approval-uid',str(os.getuid()+1),'--approval-gid',str(os.getgid()),'--development-same-uid'],capture_output=True,text=True)
    assert p.returncode != 0 and sock.read_text()=='keep'

def test_slow_clients_are_bounded_and_service_recovers(tmp_path,executor_binary):
    request=tmp_path/'request.sock';approval=tmp_path/'approval.sock';approver=os.getuid()+1
    p=subprocess.Popen([executor_binary,'--request-socket',str(request),'--approval-socket',str(approval),'--request-uid',str(os.getuid()),'--request-gid',str(os.getgid()),'--approval-uid',str(approver),'--approval-gid',str(os.getgid()),'--development-same-uid'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    clients=[];overflow=None
    try:
        wait_socket(request);wait_socket(approval)
        for _ in range(8):
            s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(str(request));clients.append(s)
        time.sleep(.1)
        overflow=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);overflow.settimeout(2);overflow.connect(str(request))
        assert overflow.recv(1)==b''
        with pytest.raises(ExecutorError,match='UNAUTHORIZED_APPROVER'):
            RustApprovalAuthorityClient(str(approval)).list_pending()
        time.sleep(5.2)
        result=RustExecutorClient(socket_path=str(request),timeout=5).submit([file_create('/tmp/recovered','x')])
        assert result['ok'] and result['status']=='PENDING_APPROVAL'
    finally:
        for s in clients+[overflow]:
            if s is not None:s.close()
        p.terminate();p.wait(timeout=3)
