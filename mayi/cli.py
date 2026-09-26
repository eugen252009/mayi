import argparse, sys
from .adapters import analyze, AnalysisError
from .parser import ShellSyntaxError
from .policy import default_policy

def main(argv=None):
    argv=list(argv) if argv is not None else sys.argv[1:]
    # Direct command form is intentionally analysis-only in this milestone.
    if argv and '-u' in argv:
        i=argv.index('-u')
        if i+1 < len(argv) and (i+2 >= len(argv) or argv[i+2] not in ('inspect','check')):
            user=argv[i+1]; command=' '.join(argv[i+2:])
            from .identity import resolve_user
            try: ident=resolve_user(user)
            except ValueError as e: print(f'ERROR: {e}'); return 2
            print(f'TARGET {ident.name} uid={ident.uid} gid={ident.gid}')
            argv=argv[:i]+['inspect',command]
    p=argparse.ArgumentParser(prog='mayi',description='inspect shell effects without executing them')
    p.add_argument('-u','--user',dest='user',help='target execution user (identity only; no setuid)')
    sub=p.add_subparsers(dest='action',required=True)
    for action in ('inspect','check'):
        q=sub.add_parser(action); q.add_argument('command')
    a=p.parse_args(argv)
    try: ops=analyze(a.command)
    except (ShellSyntaxError,AnalysisError) as e:
        print(f'ERROR: {e}'); return 2
    if a.action=='inspect':
        if a.user:
            from .identity import resolve_user
            try:
                ident=resolve_user(a.user); print(f'TARGET {ident.name} uid={ident.uid} gid={ident.gid}')
            except ValueError as e: print(f'ERROR: {e}'); return 2
        for op in ops: print(op.display())
        return 0
    decision=default_policy().evaluate(ops)
    if a.user:
        from .identity import resolve_user
        try:
            ident=resolve_user(a.user); print(f'TARGET {ident.name} uid={ident.uid} gid={ident.gid}')
        except ValueError as e: print(f'ERROR: {e}'); return 2
    print(decision.value)
    if decision.value=='APPROVAL_REQUIRED':
        print('\nOperations:\n')
        for op in ops: print(op.display())
        print('\nOptions:\n\nAllow once\nDeny\nExplain')
    return 0
if __name__=='__main__': raise SystemExit(main())
