"""Shape validation only. Only the broker authenticates rq_v2 identifiers."""
import re
REQUEST_ID_PATTERN = r'rq_(?:[0-9a-f]{32}|v2_[0-9a-f]{48}_[0-9a-f]{32}_[0-9a-f]{64}_[0-9a-f]{64})'
REQUEST_ID = re.compile('^'+REQUEST_ID_PATTERN+'$')

def valid_request_id(value):
    return isinstance(value,str) and len(value) in (35,217) and REQUEST_ID.fullmatch(value) is not None

def encoded_epoch(value):
    """Unverified presentation metadata, never authentication or authority."""
    return value.split('_')[2] if valid_request_id(value) and value.startswith('rq_v2_') else None
