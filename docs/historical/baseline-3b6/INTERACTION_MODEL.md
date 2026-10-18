# Interaction model

Space toggles exact technical fields. [ and ] move between pages; no Enter required for navigation. Navigation is accepted only while the decision input frame is empty. Resize is detected on the next polling tick; data is reflowed without changing selection.

Existing action+Enter interface is preserved: a/y/allow approve all pending in the current set, digits select indices, d/n/deny asks for all or indices, f/e/explain requests follow-up, s skips, q quits. Empty input never accepts. Input remains un-echoed. Repeated/pasted frames are rejected by the existing bounded input and quiet-window drain. Ctrl-C now exits input with an Interrupted error, sending no decision; guard restores settings.

Opening/navigating details never fetches a new challenge view or sends a decision. Before acting, console checks broker instance; each request obtains a correlated fresh view and is subject to broker state, identity, expiry, PAM and one-shot checks. UI does not mutate authorization.

Terminal guard does not hide cursor or change output modes. Existing PAM supervisor and recovery paths are unchanged. Process SIGKILL cannot run Rust destructors; no new claim of recovering an externally killed console is made. PAM-child SIGKILL recovery remains supervised and tested.

This candidate has input-level PTY coverage but not a newly qualified installed PAM-authenticated console end-to-end run. See UI_TEST_RESULTS.md.
