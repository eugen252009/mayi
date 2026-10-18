"""Package identity: tpa.json at source/build time, embedded stamp at runtime.

Never consult dpkg, environment variables, broker state or unrelated Python
package metadata. Packaging writes the stamp only into its clean package root.
"""
import json
from pathlib import Path
import re


def _validated(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]{0,127}', value):
        raise ValueError('invalid Mayi build version metadata')
    return value


def source_version():
    path = Path(__file__).resolve().parent.parent / 'executor/package/tpa.json'
    with path.open('r', encoding='ascii') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('oversized Mayi package metadata')
    return _validated(json.loads(raw)['control']['version'])


def get_version():
    path = Path(__file__).with_name('_build_version')
    try:
        with path.open('r', encoding='ascii') as stream:
            value = stream.read(130)
    except FileNotFoundError:
        return source_version()
    # A bad existing stamp is an error, never a fallback to another identity.
    if not value.endswith('\n') or value.count('\n') != 1:
        raise ValueError('invalid Mayi build version stamp')
    return _validated(value[:-1])


if __name__ == '__main__':
    # Only packaging/source identity here, regardless of a stale local stamp.
    print(source_version())
