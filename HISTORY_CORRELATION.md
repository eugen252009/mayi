# History correlation and classification

Broker lifecycle evidence (known request event +boot/instance/challenge/digest/stored owner) establishes rq_ or genuine nonqueue ch_ request identity. No arbitrary prefix or standalone auth/session/health/error event seeds a request. Group key includes binding digest and challenge to avoid unrelated reused identifiers.

Existing explicit execution bridge: (boot,execution ID) ->exactly one known broker request key. PAM bridge: exact (boot,broker instance,challenge,digest) ->exactly one known request key. Ambiguity preserved even outside request grouping cap. No timestamp/UID similarity or rq_ prefix inference. Missing rq_ on another broker row can use a unique explicit queue binding without duplicating ch_. Only proved relationships can enter --request timelines or diagnostic request association.

Standalone root execution, PAM login and session/rejection/readiness events remain visible in --events, with request association null when unknowable. Default requests never include ex_/event_N. Root/PAM's original request_id stays absent even when a separate diagnostic request_identity is known. Genuine challenge-only requests are not inherently incomplete solely because they lack queue IDs.

Late retained lifecycle records can establish a real request without PROPOSED; missing identity proof becomes a diagnostic, missing outcome becomes UNKNOWN on a real request. Broker restart/boots remain separate. No history data restores authorization, sessions or operations. No new privileged IPC/protocol/cache/persistence. Output schema2 independent of native schema1.
