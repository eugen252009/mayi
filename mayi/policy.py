from enum import Enum
from fnmatch import fnmatch
import posixpath
from .operations import Operation, Kind
class Decision(str,Enum): AUTO='AUTO'; APPROVAL='APPROVAL_REQUIRED'; DENY='DENY'
class Policy:
    def __init__(self, rules=None):
        self.rules=rules or []
    def decide(self, op):
        # Lexically canonicalize before policy matching; check every resource of
        # multi-path operations. Deny rules dominate regardless of declaration order.
        resources=[op.target]
        if op.kind is Kind.FILE_MOVE: resources.append(op.source)
        resources=[posixpath.normpath('/'+x.lstrip('/')) for x in resources]
        file_kinds=(Kind.FILE_WRITE,Kind.FILE_PATCH,Kind.FILE_CREATE,Kind.FILE_DELETE,Kind.FILE_CHMOD,Kind.FILE_CHOWN,Kind.FILE_MOVE)
        if op.kind in file_kinds and '/etc/shadow' in resources: return Decision.DENY
        for kind,pattern,decision in self.rules:
            if decision is Decision.DENY and (kind is None or kind==op.kind) and any(fnmatch(p,pattern) for p in resources): return Decision.DENY
        for kind, pattern, decision in self.rules:
            if decision is not Decision.DENY and (kind is None or kind==op.kind) and any(fnmatch(p,pattern) for p in resources): return decision
        if op.kind in (Kind.FILE_READ,): return Decision.AUTO
        return Decision.APPROVAL
    def evaluate(self, operations):
        ds=[self.decide(o) for o in operations]
        if Decision.DENY in ds: return Decision.DENY
        if Decision.APPROVAL in ds: return Decision.APPROVAL
        return Decision.AUTO

def default_policy():
    return Policy([
      (Kind.FILE_READ,'/etc/nginx/*',Decision.AUTO),
      (Kind.FILE_WRITE,'/etc/myservice/*',Decision.AUTO),
      (Kind.FILE_PATCH,'/etc/myservice/*',Decision.AUTO),
      (Kind.FILE_PATCH,'/etc/nginx/*',Decision.APPROVAL),
      (Kind.FILE_CREATE,'/tmp/*',Decision.AUTO),
      (Kind.FILE_WRITE,'/etc/nginx/*',Decision.APPROVAL),
      (Kind.SERVICE_RESTART,'*.service',Decision.APPROVAL),
    ])
