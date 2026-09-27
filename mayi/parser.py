"""Restricted shell lexer: analysis only; unsupported syntax fails closed."""
from __future__ import annotations

from dataclasses import dataclass
class ShellSyntaxError(ValueError): pass
@dataclass
class Redirection: op:str; word:str
@dataclass
class Command: words:list[str]; redirects:list[Redirection]
@dataclass
class Shell: commands:list[list[Command]]
_OPS=("&&","||",">>","2>","<<","|",";",">","<")
_QUOTED='\x01'
def lex(text:str)->list[str]:
    out=[];buf=[];quote=None;i=0;started=False
    def emit():
        nonlocal buf,started
        if started: out.append(''.join(buf));buf=[];started=False
    while i<len(text):
        c=text[i]
        if quote:
            if c==quote: quote=None
            elif c=='\\' and quote=='"' and i+1<len(text): i+=1;buf.append(text[i])
            else: buf.append(c)
            i+=1;continue
        if c in "'\"":
            if not started: buf.append(_QUOTED)
            started=True;quote=c;i+=1;continue
        if c=='\\':
            if i+1>=len(text):raise ShellSyntaxError('trailing escape')
            if not started: started=True;buf.append(_QUOTED)
            i+=1;buf.append(text[i]);i+=1;continue
        if c.isspace():
            emit()
            if c=='\n' and out and out[-1] not in (';','&&','||','|'):out.append(';')
            i+=1;continue
        found=next((op for op in _OPS if text.startswith(op,i)),None)
        if found:
            emit();out.append(found);i+=len(found);continue
        if c in '()' or c=='`' or (c=='$' and i+1<len(text) and text[i+1] in '({'):raise ShellSyntaxError('dynamic shell construct')
        started=True;buf.append(c);i+=1
    if quote:raise ShellSyntaxError('unterminated quote')
    emit()
    if out and out[-1]==';':out.pop()
    return out

def parse(text:str)->Shell:
    toks=lex(text);groups=[];pipe=[];words=[];redirects=[];i=0;lastop=False
    def finish():
        nonlocal words,redirects,pipe,lastop
        if not words:raise ShellSyntaxError('empty command')
        pipe.append(Command(words,redirects));words=[];redirects=[];lastop=False
    while i<len(toks):
        t=toks[i]
        if t in ('&&','||'):
            raise ShellSyntaxError('conditional command lists are unsupported')
        if t in (';','|'):
            finish()
            if t=='|': pass
            else:groups.append(pipe);pipe=[]
            lastop=True
        elif t in ('>','>>','2>','<','<<'):
            if i+1>=len(toks) or toks[i+1] in _OPS:raise ShellSyntaxError('redirection needs a path')
            target=toks[i+1]
            if target.startswith(_QUOTED):target=target[1:]
            redirects.append(Redirection(t,target));i+=1;lastop=False
        else:
            words.append(t[1:] if t.startswith(_QUOTED) else t);lastop=False
        i+=1
    if words:finish()
    elif pipe or lastop:raise ShellSyntaxError('trailing operator')
    if pipe:groups.append(pipe)
    if not groups and toks:raise ShellSyntaxError('invalid shell')
    return Shell(groups)
