import os
from pathlib import Path
import pytest
from mayi.adapters import analyze, AnalysisError
from mayi.operations import Kind
from mayi.parser import ShellSyntaxError
from mayi.policy import default_policy, Decision

def kinds(text, tmp_path):
    return [o.kind for o in analyze(text, str(tmp_path))]
def targets(text,tmp_path): return [(o.kind,o.target) for o in analyze(text,str(tmp_path))]

def test_echo_redirection_is_write(tmp_path):
    assert targets('echo x > file',tmp_path)[-1] == (Kind.FILE_WRITE,str(tmp_path/'file'))
    assert targets('echo x >> file',tmp_path)[-1][0] == Kind.FILE_WRITE

def test_common_adapters(tmp_path):
    assert kinds('cat file',tmp_path)[-1] == Kind.FILE_READ
    assert kinds('cat a | tee b',tmp_path)[1:] == [Kind.FILE_READ, Kind.EXEC, Kind.FILE_WRITE]
    assert kinds('cp a b',tmp_path)[-2:] == [Kind.FILE_READ, Kind.FILE_WRITE]
    assert kinds('mv a b',tmp_path)[-1] == Kind.FILE_MOVE
    assert kinds('rm file',tmp_path)[-1] == Kind.FILE_DELETE
    assert kinds('mkdir dir',tmp_path)[-1] == Kind.DIRECTORY_CREATE
    assert kinds('chmod 600 file',tmp_path)[-1] == Kind.FILE_CHMOD
    assert kinds('ln -s a b',tmp_path)[-1] == Kind.FILE_CREATE

def test_services_packages():
    assert analyze('systemctl restart foo.service')[-1].kind == Kind.SERVICE_RESTART
    assert analyze('apt install foo')[-1].kind == Kind.PACKAGE_INSTALL

def test_composition_and_paths(tmp_path):
    ops=analyze("echo 'hello world' > '../file'; cat \"input file\"",str(tmp_path/'sub'))
    assert any(o.kind==Kind.FILE_WRITE and o.target==str(tmp_path/'file') for o in ops)
    assert any(o.kind==Kind.FILE_READ and o.target.endswith('input file') for o in ops)

def test_policy_effect_not_executable(tmp_path):
    ops=analyze('echo x > /etc/shadow',str(tmp_path))
    assert default_policy().evaluate(ops) == Decision.DENY

def test_unknown_is_conservative(tmp_path):
    assert default_policy().evaluate(analyze('unknown-tool',str(tmp_path))) == Decision.APPROVAL

def test_script_expands(tmp_path):
    (tmp_path/'script.sh').write_text('echo x > /etc/myservice/config\nsystemctl restart x.service\n')
    ops=analyze('bash script.sh',str(tmp_path))
    assert any(o.kind==Kind.FILE_WRITE for o in ops)
    assert any(o.kind==Kind.SERVICE_RESTART for o in ops)

def test_bad_shell_fails_closed(tmp_path):
    with pytest.raises(ShellSyntaxError): analyze("echo 'unterminated",str(tmp_path))
    with pytest.raises(AnalysisError): analyze('echo $HOME > file',str(tmp_path))

def test_symlink_path_is_resolved(tmp_path):
    real=tmp_path/'real'; real.mkdir(); (tmp_path/'link').symlink_to(real, target_is_directory=True)
    assert analyze('echo x > link/config',str(tmp_path))[-1].target == str(real/'config')
