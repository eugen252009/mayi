"""Protocol-v5 proposal and separate approval-authority Unix clients."""
from __future__ import annotations
import json,socket
from .protocol import MAX_REQUEST_BYTES,proposal_document
class ExecutorError(RuntimeError):pass

def _frame(data):
    if len(data)>MAX_REQUEST_BYTES:raise ExecutorError('request exceeds size limit')
    return len(data).to_bytes(4,'big')+data
def _exact(s,n):
    b=bytearray()
    while len(b)<n:
        c=s.recv(n-len(b))
        if not c:raise ExecutorError('truncated framed response')
        b.extend(c)
    return bytes(b)
def _peer_uid(sock):
    import struct
    raw=sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i'))
    return struct.unpack('3i',raw)[1]
def _exchange(path,doc,timeout,expected_broker_uid=None):
    raw=json.dumps(doc,ensure_ascii=False,separators=(',',':')).encode()
    if len(raw)>MAX_REQUEST_BYTES:raise ExecutorError('request exceeds size limit')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(timeout);s.connect(path)
        if expected_broker_uid is not None and _peer_uid(s)!=expected_broker_uid:raise ExecutorError('unexpected broker peer UID')
        s.sendall(_frame(raw));n=int.from_bytes(_exact(s,4),'big')
        if n>MAX_REQUEST_BYTES:raise ExecutorError('response exceeds size limit')
        try:r=json.loads(_exact(s,n))
        except (json.JSONDecodeError,UnicodeDecodeError) as e:raise ExecutorError('invalid broker response') from e
        if not isinstance(r,dict) or r.get('response_to')!=doc.get('type'):raise ExecutorError('broker response correlation mismatch')
        return r
class DryRunExecutor:
    def submit(self,operations,**kwargs):
        d=proposal_document(operations,**kwargs)
        return {'ok':True,'validation_only':True,'request':d,'operations':len(operations)}
class RustExecutorClient:
    """Can propose requests only; intentionally exposes no approval method."""
    def __init__(self,executable='mayi-executor',socket_path=None,timeout=5,expected_broker_uid=None):
        self.socket_path=socket_path;self.timeout=timeout;self.executable=executable;self.expected_broker_uid=__import__('os').getuid() if expected_broker_uid is None else expected_broker_uid
    def submit(self,operations,**kwargs):
        if not self.socket_path:raise ExecutorError('protocol v5 proposals require the broker request socket')
        doc=proposal_document(operations,target_uid=kwargs.get('target_uid'),target_gid=kwargs.get('target_gid'))
        result=_exchange(self.socket_path,doc,self.timeout,self.expected_broker_uid)
        if not isinstance(result,dict) or not isinstance(result.get('ok'),bool):raise ExecutorError('invalid broker response schema')
        if result.get('protocol')!=5 or result.get('type')!='PROPOSE_RESPONSE':
            if not result.get('ok'):raise ExecutorError(f"{result.get('code','INTERNAL_ERROR')}: {result.get('message','rejected')}")
            raise ExecutorError('response is not correlated protocol-v5 proposal response')
        if result.get('status')!='PENDING_APPROVAL' or not all(isinstance(result.get(k),str) for k in ('broker_instance_id','challenge_id','request_digest')):raise ExecutorError('invalid proposal response')
        if len(result['broker_instance_id'])!=48 or len(result['challenge_id'])!=48 or len(result['request_digest'])!=64 or any(c not in '0123456789abcdef' for c in result['broker_instance_id']+result['challenge_id']+result['request_digest']):raise ExecutorError('invalid proposal correlation identifiers')
        return result
class RustApprovalAuthorityClient:
    """Separate approval-role transport; server authenticates SO_PEERCRED UID."""
    def __init__(self,socket_path,timeout=5,expected_broker_uid=None):self.socket_path=socket_path;self.timeout=timeout;self.expected_broker_uid=__import__('os').getuid() if expected_broker_uid is None else expected_broker_uid
    def _call(self,message):
        r=_exchange(self.socket_path,{'protocol':5,**message},self.timeout,self.expected_broker_uid)
        if not isinstance(r,dict) or not isinstance(r.get('ok'),bool):raise ExecutorError('invalid authority response')
        if not r['ok']:raise ExecutorError(f"{r.get('code','INTERNAL_ERROR')}: {r.get('message','rejected')}")
        if r.get('protocol')!=5:raise ExecutorError('invalid authority response protocol')
        if 'broker_instance_id' in message and r.get('broker_instance_id')!=message['broker_instance_id']:raise ExecutorError('authority response broker mismatch')
        if 'challenge_id' in message and r.get('challenge_id')!=message['challenge_id']:raise ExecutorError('authority response challenge mismatch')
        for field in ('request_digest','view_id'):
            if field in message and r.get(field)!=message[field]:raise ExecutorError(f'authority response {field} mismatch')
        return r
    def list_pending(self):return self._call({'type':'LIST_PENDING'})
    def get_challenge(self,broker_instance_id,challenge_id,request_digest):
        r=self._call({'type':'GET_CHALLENGE','broker_instance_id':broker_instance_id,'challenge_id':challenge_id})
        view_id=r.get('view_id')
        if r.get('type')!='CHALLENGE_VIEW' or r.get('request_digest')!=request_digest or r.get('state')!='PENDING_APPROVAL' or not isinstance(view_id,str) or len(view_id)!=48 or any(c not in '0123456789abcdef' for c in view_id):raise ExecutorError('invalid approval view correlation')
        return r
    def decide(self,decision,broker_instance_id,challenge_id,request_digest,view_id):
        names={'approve':'APPROVE_CHALLENGE','deny':'DENY_CHALLENGE','explain':'EXPLAIN_CHALLENGE'}
        if decision not in names:raise ValueError('decision must be approve, deny, or explain')
        return self._call({'type':names[decision],'broker_instance_id':broker_instance_id,'challenge_id':challenge_id,'request_digest':request_digest,'view_id':view_id})
