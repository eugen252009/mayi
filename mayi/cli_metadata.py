"""Shared local-only metadata dispatch; never imports an IPC client."""
import sys
from .version import get_version


def dispatch_metadata(argv, program, help_text):
    if not argv or argv[0] not in ('--help', '-h', '--version', '-V'):
        return None
    if len(argv) != 1:
        print('MAYI_CLI_ERROR: metadata options must be used alone (see --help)', file=sys.stderr)
        return 12
    if argv[0] in ('--help', '-h'):
        print(help_text)
        return 0
    try:
        version = get_version()
    except (OSError, ValueError, KeyError, TypeError):
        print('MAYI_CLI_ERROR: build version metadata is unavailable or invalid', file=sys.stderr)
        return 15
    print(program + ' ' + version)
    return 0
