import pytest
from dataclasses import replace
from mayi.adapters import analyze
from mayi.operations import Operation,Kind
from mayi.policy import Policy,Decision
from mayi.protocol import canonical_operations
from mayi.mutations import file_patch

def test_script_invocation_redirection_is_not_silently_lost(tmp_path):
    (tmp_path/'empty.sh').write_text('')
    # Must not be interpreted as an empty harmless request.
    ops=analyze('bash empty.sh > /etc/shadow',str(tmp_path))
    assert any(o.kind is Kind.FILE_WRITE and o.target.endswith('/etc/shadow') for o in ops)

def test_quoted_operator_is_not_redirection(tmp_path):
    ops=analyze('echo ">" /etc/shadow',str(tmp_path))
    assert not any(o.kind is Kind.FILE_WRITE for o in ops)

def test_empty_quoted_argument_is_preserved():
    op=analyze("echo ''")[0]
    assert op.args==('',)

def test_dangling_condition_is_rejected():
    with pytest.raises(ValueError): analyze('echo x &&')

def test_policy_deny_dominates_auto_and_move_source_checked():
    policy=Policy([(Kind.FILE_CREATE,'/etc/**',Decision.DENY),(Kind.FILE_CREATE,'/**',Decision.AUTO)])
    assert policy.decide(Operation(Kind.FILE_CREATE,'/etc/shadow')) is Decision.DENY
    assert policy.decide(Operation(Kind.FILE_MOVE,'/tmp/dest',source='/etc/shadow')) is Decision.DENY

def test_protocol_does_not_drop_modeled_patch_metadata():
    op=file_patch('/etc/x','a','b',mode='0600')
    with pytest.raises(ValueError): canonical_operations([op])

def test_protocol_rejects_path_aliases():
    with pytest.raises(ValueError): canonical_operations([Operation(Kind.FILE_CREATE,'//etc/x')])
    with pytest.raises(ValueError): canonical_operations([Operation(Kind.FILE_CREATE,'/etc/../x')])

def test_protocol_does_not_drop_package_version():
    with pytest.raises(ValueError): canonical_operations([Operation(Kind.PACKAGE_INSTALL,'foo',version='1.0')])
