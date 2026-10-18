import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest
from mayi import cli, approval_cli, version


@pytest.mark.parametrize('flag',['--version','-V','--help','-h'])
def test_metadata_is_local_in_actual_main(flag,monkeypatch,capsys):
    def forbidden(*a,**kw):raise AssertionError('metadata crossed execution/IPC boundary')
    monkeypatch.setattr(cli,'resolve_executable',forbidden)
    monkeypatch.setattr(cli,'RustExecutorClient',forbidden)
    import socket
    monkeypatch.setattr(socket,'socket',forbidden)
    assert cli.main([flag])==0
    text=capsys.readouterr().out
    assert ('mayi '+version.source_version()) in text if 'version' in flag or flag=='-V' else 'Usage:' in text


@pytest.mark.parametrize('flag',['--version','-V','--help','-h'])
def test_approver_metadata_never_execs_console(flag,monkeypatch,capsys):
    def forbidden(*a,**kw):raise AssertionError('metadata started console/IPC')
    monkeypatch.setattr(approval_cli.os,'execv',forbidden)
    import socket
    monkeypatch.setattr(socket,'socket',forbidden)
    monkeypatch.setattr(sys,'argv',['mayi-approve',flag])
    with pytest.raises(SystemExit) as e:approval_cli.main()
    assert e.value.code==0
    text=capsys.readouterr().out
    assert ('mayi-approve '+version.source_version()) in text if 'version' in flag or flag=='-V' else 'Usage:' in text


@pytest.mark.parametrize('argv',[['--unknown'],['-Z'],['-'],['--version','extra'],['--help','/usr/bin/true'],['-V','--help'],['--']])
def test_usage_errors_never_submit(argv,monkeypatch,capsys):
    def forbidden(*a,**kw):raise AssertionError('invalid option submitted')
    monkeypatch.setattr(cli,'RustExecutorClient',forbidden)
    monkeypatch.setattr(cli,'resolve_executable',forbidden)
    assert cli.main(argv)==12
    assert 'MAYI_CLI_ERROR' in capsys.readouterr().err


@pytest.mark.parametrize('prefix',[[],['--']])
@pytest.mark.parametrize('args',[
    ['/usr/bin/echo','hallo'], ['/usr/bin/bash','--version'],
    ['/usr/bin/bash','-c','echo hallo'],
    ['/usr/bin/echo','','space containing value','grüße','--help','--version','; not a shell'],
    ['/usr/bin/echo','--','-V','-h']])
def test_real_dispatch_submits_exact_operation_and_requires_decision(prefix,args,monkeypatch):
    seen=[]
    class Client:
        def __init__(self,**kw):pass
        def submit(self,operations):
            seen.extend(operations)
            return dict(broker_instance_id='a'*48,challenge_id='b'*48,request_digest='c'*64)
        def request_status(self,*a):return {'status':'DENIED'}
        def consume_approved(self,*a):raise AssertionError('denial bypassed')
    monkeypatch.setattr(cli,'RustExecutorClient',Client)
    assert cli.main(prefix+args)==10
    from mayi.protocol import canonical_operations
    assert canonical_operations(seen)==[{'type':'exec','executable':cli.resolve_executable(args[0]),'argv':args}]


def test_separator_bypasses_internal_words_and_hyphen_dispatch_only(monkeypatch):
    seen=[]
    monkeypatch.setattr(cli,'_execute_request',lambda argv:seen.append(argv) or 99)
    for word in ['history','inspect','check','version','--version','-command']:
        assert cli.main(['--',word,'--help'])==99
        assert seen[-1]==[word,'--help']
    assert cli.main(['version'])==99  # intentionally not reserved as cosmetic alias
    assert cli.main(['historyX'])==99


def test_untrusted_separator_never_reaches_broker(monkeypatch,tmp_path):
    monkeypatch.setattr(cli,'RustExecutorClient',lambda **kw:pytest.fail('untrusted path crossed boundary'))
    for argv in [['--','./echo'],['--',str(tmp_path/'thing')],['--',''],['--','/tmp/echo']]:
        assert cli.main(argv)==12


def test_history_dispatch_and_help(monkeypatch,capsys):
    from mayi import history
    called=[];monkeypatch.setattr(history,'main',lambda argv:called.append(argv) or 23)
    assert cli.main(['history','--json'])==23 and called==[['--json']]


def test_approver_status_remains_separate(monkeypatch):
    from mayi import approval_status
    seen=[];monkeypatch.setattr(approval_status,'main',lambda argv:seen.append(argv) or 24)
    monkeypatch.setattr(sys,'argv',['mayi-approve','status','--watch','--json'])
    with pytest.raises(SystemExit) as e:approval_cli.main()
    assert e.value.code==24 and seen==[['--watch','--json']]


def test_empty_cli_compatibility(capsys):
    assert cli.main([])==2 and 'Usage:' in capsys.readouterr().out


def test_embedded_identity_wins_over_unrelated_source_or_package(tmp_path):
    module=tmp_path/'version.py';module.write_bytes(Path(version.__file__).read_bytes())
    spec=importlib.util.spec_from_file_location('isolated_version',module);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
    (tmp_path/'_build_version').write_text('77.8~own-build\n')
    assert v.get_version()=='77.8~own-build'
    (tmp_path/'_build_version').write_text('bad\nversion\n')
    with pytest.raises(ValueError):v.get_version()
    (tmp_path/'_build_version').unlink()
    with pytest.raises(FileNotFoundError):v.get_version()  # never queries host dpkg


@pytest.mark.parametrize('args',[['--version'],['-V'],['--help'],['-h'],['history','--help']])
def test_source_subprocess_metadata_offline(args):
    # Actual main with every Python socket operation poisoned in a fresh process.
    code="import socket; socket.socket=lambda *a,**k:(_ for _ in ()).throw(AssertionError('IPC')); from mayi.cli import main; raise SystemExit(main())"
    cp=subprocess.run([sys.executable,'-c',code,*args],capture_output=True,text=True)
    assert cp.returncode==0 and cp.stdout and not cp.stderr
    if args[0] in ['--version','-V']:assert cp.stdout=='mayi '+version.source_version()+'\n'


def test_ordinary_command_offline_is_not_a_metadata_success(monkeypatch,capsys):
    class Client:
        def __init__(self,**kw):pass
        def submit(self,*a):raise FileNotFoundError('broker unavailable')
    monkeypatch.setattr(cli,'RustExecutorClient',Client)
    assert cli.main(['/usr/bin/bash','--version'])==15
    assert 'MAYI_BROKER_ERROR' in capsys.readouterr().err


def test_package_version_source_and_stamp_generation_are_not_duplicated():
    root=Path(__file__).resolve().parents[1]
    assert version.source_version()==json.loads((root/'executor/package/tpa.json').read_text())['control']['version']
    script=(root/'executor/package/build-deb.sh').read_text()
    assert 'VERSION=$(python3 "$ROOT/mayi/version.py")' in script
    assert 'mayi_${VERSION}_amd64.deb' in script and '/mayi/_build_version' in script
    assert '0.4.1-10~status2' not in script
