"""Protocol v5 proposal construction. Client digests are identifiers, never approval."""
from __future__ import annotations
import json,os,posixpath
from .operations import Operation,Kind
PROTOCOL_VERSION=5
MAX_REQUEST_BYTES=512*1024

def _path(p):
    if not isinstance(p,str) or not p.startswith('/') or p=='/' or '\x00' in p or p!=posixpath.normpath(p) or p.startswith('//'):
        raise ValueError('path is not canonical absolute logical path')
    return p

def _op(o):
    k=o.kind
    if k is Kind.EXEC: return {'args':list(o.args),'executable':o.target,'type':'exec'}
    if k is Kind.FILE_PATCH:
        if o.mode or o.owner: raise ValueError('FilePatch metadata is unsupported')
        return {'expected_base_sha256':o.expected_base_sha256,'expected_result_sha256':o.expected_result_sha256,'patch':[dict(x) for x in o.patch],'path':_path(o.target),'type':'file_patch'}
    if k is Kind.FILE_CREATE: return {'content':o.content,'expected_result_sha256':o.expected_result_sha256,'mode':o.mode or '0644','path':_path(o.target),'type':'file_create'}
    if k is Kind.FILE_DELETE: return {'expected_sha256':o.expected_base_sha256,'path':_path(o.target),'type':'file_delete'}
    if k is Kind.FILE_MOVE: return {'destination':_path(o.target),'expected_source_sha256':o.expected_base_sha256,'source':_path(o.source),'type':'file_move'}
    if k in (Kind.FILE_READ,Kind.FILE_WRITE): return {'mode':'replace','path':_path(o.target),'type':k.value.lower()}
    if k is Kind.FILE_CHMOD: return {'mode':o.mode,'path':_path(o.target),'type':'file_chmod'}
    if k is Kind.FILE_CHOWN: return {'owner':o.owner,'path':_path(o.target),'type':'file_chown'}
    if k is Kind.DIRECTORY_CREATE: return {'path':_path(o.target),'type':'directory_create'}
    if k.name.startswith('SERVICE_'): return {'service':o.target,'type':k.value.lower()}
    if k.name.startswith('PACKAGE_'):
        if o.version: raise ValueError('package versions are unsupported')
        return {'package':o.target,'type':k.value.lower()}
    raise ValueError(f'unsupported operation kind: {k}')

def canonical_operations(operations): return [_op(o) for o in operations]
def proposal_document(operations,*,target_uid=None,target_gid=None):
    uid=os.getuid() if target_uid is None else target_uid;gid=os.getgid() if target_gid is None else target_gid
    if type(uid) is not int or type(gid) is not int or not 0<=uid<=0xffffffff or not 0<=gid<=0xffffffff:raise ValueError('target UID/GID must be bounded nonnegative integers')
    return {'operations':canonical_operations(operations),'protocol':PROTOCOL_VERSION,'target':{'gid':gid,'uid':uid},'type':'PROPOSE_REQUEST'}
def request_document(operations,**kwargs):
    allowed={'target_uid','target_gid'}
    if set(kwargs)-allowed: raise ValueError('protocol v4 authority fields and unknown proposal fields are not accepted')
    return proposal_document(operations,target_uid=kwargs.get('target_uid'),target_gid=kwargs.get('target_gid'))
def request_json(operations,**kwargs): return json.dumps(proposal_document(operations,**kwargs),ensure_ascii=False,sort_keys=True,separators=(',',':'))
def canonical_bytes(operations,**binding):
    """Canonical integrity material only; never accepted as approval evidence."""
    return json.dumps({'operations':canonical_operations(operations),'protocol':PROTOCOL_VERSION,**binding},ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def digest(operations,**binding):
    import hashlib
    return hashlib.sha256(canonical_bytes(operations,**binding)).hexdigest()
