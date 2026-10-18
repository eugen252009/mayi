# Privacy and security

No default audit payload contains full executable/arguments, environment, stdout/stderr, file contents, PAM passwords or conversation responses, session tokens, raw view IDs, private keys or API credentials. The logger receives a fixed projection of typed metadata. Child output continues through the existing bounded execution response, not the audit channel. UI technical details still display exact arguments to the approver; that is not service audit logging.

Request-ID, challenge, instance and digest identify/bind stored operations but alone cannot authorize one. Kernel peer identity/NSS roles/PAM or an authenticated process/terminal-bound session plus a fresh bound view remain necessary. The potentially sensitive raw view/session nonces are never logged; only a view hash is exposed.

Controls and non-ASCII in diagnostic values are escaped. Reasons use bounded server codes/ErrorKind rather than arbitrary exception strings. Requesters cannot choose field names, priority, identifier, trusted underscore fields or event names. Strict input validation and the existing limits remain in force.

Journal readers may see operational metadata. Existing root/systemd-journal/adm permissions and distro ACL policy govern access; no group, ACL, socket permission or journal access change was made. This feature does not grant the mayi-requester group read access. Check local journal ACLs; do not widen access for convenience.

Custom MAYI_* and SYSLOG_IDENTIFIER fields are not cryptographic proof: other local programs can submit similar user fields. Interpret records with trusted _SYSTEMD_UNIT, _PID, _UID, _EXE and boot/invocation metadata. Test process records are not installed-service records. Root/compromised emitting service can lie; this is not tamper-proof auditing.

Qualification uses synthetic credentials only in disposable VMs, generated in guest memory, never embedded in argv/environment/scripts or exported audit evidence. Temporary guest shadow hashes are runtime PAM fixtures, not shipped artifacts. Raw native JSON is checked for unique argument/stdout/stderr marker leakage. Original releases, staging and operator installation remain unchanged.
