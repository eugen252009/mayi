# Initial terminal compatibility

Frozen renderer measured compact/details first pages:
120x40:12/33 lines;100x30:12/31;80x24:12/25;60x20:13/21;40x12:12/13;30x8:13/15.
Thus overflow is reproducible even at common sizes in details, not merely aesthetic. The old page budget subtracts8 before wrapping optional chrome and height is clamped to>=12. Full raw captures and JSON matrix are in audit/.

T1 MEDIUM: requester Waiting tick is a fixed long ASCII line with clear-current-line. At30/40 columns it wraps; subsequent clear only erases the last physical line, causing accumulating output. Reproduce Waiting.tick on a narrow supported PTY/stderr. Fix bound animation text to the actual stream's terminal width (reserve last column), no stdout output or ANSI on unsupported/redirected stderr. Acceptance maximum visible line <width at every requested size; clock-driven feedback and stop cleanup retained.

No-ANSI console uses scrollback rather than screen clearing; acceptable documented limitation, not grounds for a new full-screen framework. Invalid UTF8 remains rejected; Unicode/bidi/control/newline disclosure remains inert. Short status detail dumps may deliberately need scrollback, but primary approval controls must not require it at supported30x8.
