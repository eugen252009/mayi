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

def recv_exact(sock,size):
    data=bytearray()
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        if not chunk: raise EOFError('truncated response')
        data.extend(chunk)
    return bytes(data)

def wait_socket(path):
    for _ in range(100):
        if path.exists(): return
        time.sleep(.01)
    raise AssertionError('executor socket did not appear')

def test_socket_peer_identity_and_framed_request(tmp_path, executor_binary):
    sock=tmp_path/'request.sock'; auth=tmp_path/'approval.sock'
    p=subprocess.Popen([executor_binary,'--request-socket',str(sock),'--approval-socket',str(auth),'--request-gid',str(os.getgid()),'--approval-gid',str(os.getgid()),'--development-same-uid'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        wait_socket(sock);wait_socket(auth)
        assert stat.S_IMODE(sock.stat().st_mode)==0o660 and sock.stat().st_gid==os.getgid()
        assert stat.S_IMODE(auth.stat().st_mode)==0o660 and auth.stat().st_gid==os.getgid()
        with pytest.raises(ExecutorError, match='UNSUPPORTED_OPERATION'):
            RustExecutorClient(socket_path=str(sock)).submit([file_create('/tmp/socket','x')])
        assert RustApprovalAuthorityClient(str(auth)).list_pending()['pending']==[]
        result=RustExecutorClient(socket_path=str(sock)).submit([Operation(Kind.EXEC,'/usr/bin/true',('/usr/bin/true',))])
        assert result['ok'] and result['status']=='PENDING_APPROVAL'
        authority = RustApprovalAuthorityClient(str(auth))
        pending = authority.list_pending()['pending']
        assert len(pending)==1
        view = authority.get_challenge(result['broker_instance_id'], result['challenge_id'], result['request_digest'])
        request = {'type':'APPROVE_CHALLENGE','protocol':5,'broker_instance_id':result['broker_instance_id'],'challenge_id':result['challenge_id'],'request_digest':result['request_digest'],'view_id':view['view_id']}
        payload = __import__('json').dumps(request,separators=(',',':')).encode()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as raw:
            raw.settimeout(2);raw.connect(str(auth));raw.sendall(len(payload).to_bytes(4,'big')+payload)
            size=int.from_bytes(recv_exact(raw,4),'big');response=__import__('json').loads(recv_exact(raw,size))
        assert response['ok'] is False and response['code']=='PAM_AUTH_REQUIRED'
        status=RustExecutorClient(socket_path=str(sock)).request_status(result['broker_instance_id'],result['challenge_id'],result['request_digest'])
        assert status['status']=='PENDING'
    finally:
        p.terminate(); p.wait(timeout=3)

def test_socket_path_regular_file_is_not_removed(tmp_path, executor_binary):
    sock=tmp_path/'request.sock'; auth=tmp_path/'approval.sock';sock.write_text('keep')
    p=subprocess.run([executor_binary,'--request-socket',str(sock),'--approval-socket',str(auth),'--request-gid',str(os.getgid()),'--approval-gid',str(os.getgid()),'--development-same-uid'],capture_output=True,text=True)
    assert p.returncode != 0 and sock.read_text()=='keep'

def test_slow_clients_are_bounded_and_service_recovers(tmp_path,executor_binary):
    request=tmp_path/'request.sock';approval=tmp_path/'approval.sock'
    p=subprocess.Popen([executor_binary,'--request-socket',str(request),'--approval-socket',str(approval),'--request-gid',str(os.getgid()),'--approval-gid',str(os.getgid()),'--development-same-uid'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    clients=[];overflow=None
    try:
        wait_socket(request);wait_socket(approval)
        for _ in range(8):
            s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(str(request));clients.append(s)
        time.sleep(.1)
        overflow=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);overflow.settimeout(2);overflow.connect(str(request))
        assert overflow.recv(1)==b''
        assert RustApprovalAuthorityClient(str(approval)).list_pending()['pending']==[]
        time.sleep(5.2)
        result=RustExecutorClient(socket_path=str(request),timeout=5).submit([Operation(Kind.EXEC,'/usr/bin/true',('/usr/bin/true',))])
        assert result['ok'] and result['status']=='PENDING_APPROVAL'
    finally:
        for s in clients+[overflow]:
            if s is not None:s.close()
        p.terminate();p.wait(timeout=3)
