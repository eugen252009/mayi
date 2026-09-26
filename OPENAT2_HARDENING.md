# openat2 implementation status — not a mutation safety claim

The prior Rust implementation uses Linux `openat2` with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` for parent lookup and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` for final-component lookup. It does not use `RESOLVE_NO_XDEV`; mount crossings are allowed.

These flags constrain path lookup, not subsequent directory topology or commit races. The audit reproduced a resolved parent directory being moved outside the fake root before a descriptor-relative commit. Mount/backing-object crossings are also not confined by these flags.

Filesystem mutation is now rejected pending an independent approval authority. Do not infer that openat2 makes the remaining implementation safe or re-enable it based on these lookup flags. Before any later execution milestone, define a trusted topology/mount model, pin the root for broker lifetime, and independently audit commit semantics.
