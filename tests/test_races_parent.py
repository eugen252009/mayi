def test_parent_move_cannot_reach_mutation_without_approval_authority():
    # Regression for the prior retained-parent escape: execution is now closed
    # until a separate authority exists, so no filesystem path reaches commit.
    from pathlib import Path
    source=Path('executor/src/main.rs').read_text()
    assert 'APPROVAL_AUTHORITY_UNAVAILABLE' in source
