"""Evidence-only Porta advice. Never authority, IPC, retries or state mutation.

Callers must supply already identity/correlation/credential-validated events.
Absence of events never grants SAFE_TO_RECREATE_REQUEST.
"""


def classify_recovery(events):
    completed = set()
    claimed = False
    fenced = False
    for event in events:
        name = event.get('event')
        unit = event.get('source_unit')
        broker = unit == 'mayi-broker.service'
        executor = unit == 'mayi-privileged-executor.service'
        if broker and name == 'REQUEST_INVALIDATED' and event.get('state') == 'INVALIDATED' and event.get('invalidation_reason') == 'BROKER_STOPPING':
            fenced = True
        if name in ('CONSUMED','QUEUE_DISPATCH_STARTED','EXECUTION_DISPATCH_STARTED','EXECUTION_STARTED','EXECUTION_FINISHED','QUEUE_EXECUTION_FINISHED'):
            claimed = True
        if (broker and name in ('EXECUTION_FINISHED','QUEUE_EXECUTION_FINISHED')) or (executor and name == 'EXECUTION_FINISHED'):
            state = event.get('state')
            if state == 'SUCCEEDED' and event.get('exit_code') == 0 and (executor or event.get('result') == 0):
                completed.add('SUCCEEDED')
            elif state == 'FAILED' and (event.get('exit_code') not in (None,0) or event.get('signal') is not None or (broker and event.get('result') == 14)):
                completed.add('FAILED')
    # Contradictory trusted evidence is not made safe by choosing one record.
    if len(completed) == 1 and not fenced:
        return 'COMPLETED'
    if fenced and not claimed and not completed:
        return 'SAFE_TO_RECREATE_REQUEST'
    return 'RECONCILIATION_REQUIRED'
