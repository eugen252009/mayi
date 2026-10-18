"""Documentation path contracts, independent of TPA/root services or release builds."""
from pathlib import Path
import posixpath
import re
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = set('''HISTORY_DESIGN HISTORY_SCHEMA HISTORY_CORRELATION HISTORY_SECURITY
STATUS_DESIGN QUEUE_STATE_MAPPING STATUS_PROTOCOL STATUS_SECURITY STATUS_JSON_SCHEMA
STATUS_WATCH_MODE CLI_DISPATCH_DESIGN CLI_COMPATIBILITY HISTORY_CLASSIFICATION
HISTORY_EVENTS_MODE HISTORY_JSON_COMPATIBILITY BROKER_EPOCH RESTART_INVALIDATION
UPDATE_PREFLIGHT PORTA_RECOVERY_CONTRACT EXECUTION_OUTCOME_SEMANTICS UX_USAGE'''.split())


def packaged_docs():
    script = (ROOT / 'executor/package/build-deb.sh').read_text()
    match = re.search(r'for doc in (.*?); do', script, re.S)
    assert match, 'documentation install list missing'
    paths = [p + '.md' for p in match.group(1).replace('\\\n', ' ').split()]
    assert len(paths) == len(set(paths)) == len(EXPECTED)
    assert {Path(p).stem for p in paths} == EXPECTED, 'intended documentation omitted or added'
    assert '"$ROOT/docs/$doc.md" "$PKGROOT/usr/share/doc/mayi/$doc.md"' in script
    return paths


def test_exact_three_root_markdown_entrypoints():
    paths = [p for p in ROOT.iterdir() if p.suffix.lower() == '.md']
    assert sorted(p.name for p in paths) == ['AGENTS.md', 'PROJECT_STATUS.md', 'README.md']
    assert all(p.is_file() and not p.is_symlink() for p in paths)
    assert (ROOT / 'docs/SECURITY.md').is_file()


def test_packaged_documentation_set_and_relative_link_closure():
    paths = packaged_docs()
    for path in paths:
        assert not path.startswith('/') and '..' not in Path(path).parts
        source = ROOT / 'docs' / path
        assert source.is_file(), path
        for link in re.findall(r'\[[^\]\n]*\]\(([^)\n]+)\)', source.read_text()):
            url = urllib.parse.urlsplit(link)
            if url.scheme or not url.path:
                continue
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), url.path))
            assert target in paths, (path, link, 'installed relative link would be missing')


def test_installed_manpage_document_references_have_package_inputs():
    paths = packaged_docs()
    for manual in ['mayi.1', 'mayi-workflow.7']:
        text = (ROOT / 'man' / manual).read_text()
        for path in re.findall(r'/usr/share/doc/mayi/([A-Za-z0-9_./-]+\.md)', text):
            assert path in paths, (manual, path)
    assert (ROOT / 'executor/package/usr/share/doc/mayi/copyright').is_file()
