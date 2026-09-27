def test_symlink_race_hooks_are_not_in_normal_execution_path():
    # Test hooks were an uncontrolled production environment input. Mutation
    # execution is fail-closed pending independent approval; no hook can pause it.
    from pathlib import Path
    source=Path('executor/src/main.rs').read_text()
    assert 'protocol-v4 single-socket service is disabled' in source
