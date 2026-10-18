# Preserved failures, exact causes and corrective evidence

Initial audit and prebuild failures remain in ../ux-0.4.1-11-ui1/: termios-bytes baseline logger failure and same-frozen-package retry; synthetic concatenated-page test separator; real zero-width requester-PTY bug fixed before ui1 build; missing standalone debug prerequisite; and pre-existing development-mode production-key startup refusal reproduced from fresh frozen source. EARLIER_FAILURES.md records those details. No old exit or evidence file was overwritten.

## ui1 package rejected, not silently replaced

ui1 SHA256 f25886d31b95840a927f3a6033c863f233a29d72a263b05003f7cab0fbcb7a8b remains in its original qualification directory, with UI1_RESULT.json = UX NO-GO. Debian11's original40-gate process exit1 failed live-status-watch because the human watcher exited before interruption; Debian12/13 exited0. A direct installed Debian11 reproduction showed terminal_size()=(0,0) on an initially unsized PTY. Python3.9 shutil can return the real zero geometry instead of applying fallback. This was a genuine new-platform watch bug, not relabeled a fixture pass.

ui2 is a new version, source and artifact hash. It normalizes the fallback to positive80x24 and adds a Python3.9-style zero-size unit test plus actual installed unsized-PTY and full watch tests on all three platforms. It also leaves alternate screen BEFORE emitting fallback errors, reserves asynchronous queue notices in the bounded current-set canvas, and describes raw RUNNING context conservatively as dispatched/start-unconfirmed here.

## ui2 original overlap fixture rejects pipelined input

The41-gate original ui2 runs retain exit1 on all platforms, with40 other gates PASS and one overlapping-authentication fixture FAIL. The transcript ends with the existing secure “additional terminal input after decision frame” rejection; no authority was granted to the failed authenticator. The inherited fixture used ANY new header/prompt as an acknowledgement of Space. A legitimate unsolicited queue-notice redraw produced the same header without toggling details, so the fixture sent another framed action before the previous one was acknowledged.

The corrected fixture waits for the EXPECTED toggled More/Less footer, not merely an arbitrary new header. It does not remove the input guard, weaken authentication, add retries to Mayi, alter the candidate or skip a security assertion. Same immutable ui2 package in fixture-retry/: overlapping authentication, queue notice/current-set binding/unsized fallback/visible watch errors, decision race and live watch all PASS/exit0 on Debian11/12/13. The independent audit requires the original guard failure AND this separate same-artifact retry explicitly. It does not report the original processes as exit0 or41/41.

All current source gates and affected installed properties are independently checked. Data assertions for failed authentication, original-set-only approval, wrong-owner/digest/replay, one-shot markers, strict expiry, terminal restoration and no mutation remain intact.
