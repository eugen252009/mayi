"""Construction and presentation helpers for explicit filesystem mutations.

These helpers never execute mutations. They turn already-read unprivileged
content into an approval-bound Operation.
"""
from __future__ import annotations
import difflib, hashlib
from .operations import Operation, Kind

def sha256_bytes(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def sha256_text(text: str) -> str: return sha256_bytes(text.encode())
def file_patch(path: str, old: str, new: str, *, mode="", owner="") -> Operation:
    if old == new: raise ValueError("patch has no change")
    if not old: raise ValueError("empty base should use FileCreate")
    return Operation(Kind.FILE_PATCH,path,mode=mode,owner=owner,expected_base_sha256=sha256_text(old),expected_result_sha256=sha256_text(new),patch=({"old":old,"new":new},))
def file_create(path: str, content: str, *, mode="0644") -> Operation:
    return Operation(Kind.FILE_CREATE,path,mode=mode,content=content,expected_result_sha256=sha256_text(content))
def file_delete(path: str, current: bytes|str) -> Operation:
    data=current.encode() if isinstance(current,str) else current
    return Operation(Kind.FILE_DELETE,path,expected_base_sha256=sha256_bytes(data))
def file_move(source: str, destination: str, current: bytes|str) -> Operation:
    data=current.encode() if isinstance(current,str) else current
    return Operation(Kind.FILE_MOVE,destination,source=source,expected_base_sha256=sha256_bytes(data))
def unified_diff(path: str, old: str, new: str) -> str:
    return ''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile=path,tofile=path))

def approval_text(op: Operation, old: str|None=None, new: str|None=None) -> str:
    if op.kind is Kind.FILE_PATCH:
        diff=unified_diff(op.target,old,new) if old is not None and new is not None else '\n'.join(f"- {e['old']}\n+ {e['new']}" for e in op.patch)
        return f"MAYI REQUEST\n\nPATCH {op.target}\n{diff}\nBase:\nsha256: {op.expected_base_sha256}\n\nResult:\nsha256: {op.expected_result_sha256}"
    return f"MAYI REQUEST\n\n{op.display()}"
