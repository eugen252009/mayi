"""Conservative semantic adapters for a deliberately small command set."""
from pathlib import Path
import os
from .operations import Operation, Kind
from .parser import parse, ShellSyntaxError, Command

class AnalysisError(ValueError): pass

def path(value, cwd):
    if any(x in value for x in ('\x00','$')): raise AnalysisError("dynamic path")
    p=Path(value)
    if not p.is_absolute(): p=Path(cwd)/p
    # Resolve existing components; resolve(strict=False) also removes traversal.
    return str(p.resolve(strict=False))

def args_after(words, flags=()): return [x for x in words[1:] if x not in flags and not x.startswith('-')]
def fileop(kind, value, cwd): return Operation(kind, path(value,cwd))

def command_ops(c: Command, cwd, depth=0, max_script_bytes=65536):
    if not c.words: raise AnalysisError("empty command")
    name=c.words[0]; w=c.words; ops=[]
    if any('$' in x for x in w): raise AnalysisError("environment expansion is not analyzable")
    redir_ops=[]
    for r in c.redirects:
        if r.op in ('>','>>','2>'): redir_ops.append(fileop(Kind.FILE_WRITE,r.word,cwd))
        elif r.op in ('<','<<'): redir_ops.append(fileop(Kind.FILE_READ,r.word,cwd))
    if name in ('bash','sh') and len(w)>=2 and not w[1].startswith('-'):
        if depth>=4: raise AnalysisError("script nesting limit")
        script=Path(path(w[1],cwd))
        try: text=script.read_text()
        except OSError as e: raise AnalysisError(f"cannot read script: {e}")
        if len(text)>max_script_bytes: raise AnalysisError("script size limit")
        parsed=parse(text)
        for pipe in parsed.commands:
            for sub in pipe: ops += command_ops(sub,cwd,depth+1,max_script_bytes)
        return redir_ops+ops
    ops.append(Operation(Kind.EXEC,name,tuple(w[1:])))
    ops.extend(redir_ops)
    def one(kind,x): ops.append(fileop(kind,x,cwd))
    if name in ('cat','grep'):
        for x in args_after(w,('-n','-i','-v','-r','-R','--')): one(Kind.FILE_READ,x)
    elif name=='cp' and len(w)>=3:
        src=args_after(w,('-f','-i','-r','-R','--'))
        if len(src)>=2:
            for x in src[:-1]: one(Kind.FILE_READ,x)
            one(Kind.FILE_WRITE,src[-1])
    elif name=='mv' and len(w)>=3:
        a=args_after(w,('-f','-i','--'))
        if len(a)>=2: ops.append(Operation(Kind.FILE_MOVE,path(a[-1],cwd),source=path(a[0],cwd)))
    elif name=='rm':
        for x in args_after(w,('-f','-r','-R','--')): one(Kind.FILE_DELETE,x)
    elif name=='mkdir':
        for x in args_after(w,('-p','--')): one(Kind.DIRECTORY_CREATE,x)
    elif name=='chmod':
        a=args_after(w,('-R','--'))
        if len(a)>=2:
            for x in a[1:]: ops.append(Operation(Kind.FILE_CHMOD,path(x,cwd),mode=a[0]))
    elif name=='chown':
        a=args_after(w,('-R','--'))
        if len(a)>=2:
            for x in a[1:]: ops.append(Operation(Kind.FILE_CHOWN,path(x,cwd),owner=a[0]))
    elif name=='ln' and len(w)>=3:
        a=args_after(w,('-s','-f','--'))
        if len(a)>=2: one(Kind.FILE_CREATE,a[-1])
    elif name=='tee':
        for x in args_after(w,('-a','--')): one(Kind.FILE_WRITE,x)
    elif name=='systemctl' and len(w)>=2:
        action=w[1]; mp={'status':Kind.SERVICE_STATUS,'start':Kind.SERVICE_START,'stop':Kind.SERVICE_STOP,'restart':Kind.SERVICE_RESTART}
        if action in mp:
            for x in w[2:]:
                if not x.startswith('-'): ops.append(Operation(mp[action],x))
    elif name in ('apt','apt-get','dpkg') and len(w)>=2:
        action=w[1]; mp={'install':Kind.PACKAGE_INSTALL,'remove':Kind.PACKAGE_REMOVE,'purge':Kind.PACKAGE_REMOVE,'upgrade':Kind.PACKAGE_UPGRADE,'--install':Kind.PACKAGE_INSTALL,'--remove':Kind.PACKAGE_REMOVE}
        if action in mp:
            for x in w[2:]:
                if not x.startswith('-'): ops.append(Operation(mp[action],x))
    elif name not in ('echo','printf','true','pwd'):
        # EXEC remains visible; policy's default for it is approval.
        pass
    return ops

def analyze(text, cwd=None):
    cwd=cwd or os.getcwd(); shell=parse(text); result=[]
    for pipeline in shell.commands:
        for c in pipeline: result.extend(command_ops(c,cwd))
    return result
