> Archive view: maintainer-local paths have been omitted. Commands containing
> `[local-only path omitted]` are historical records, not runnable instructions.
> Original bytes remain at the commit/path recorded by the documentation checker.

# Mayi UI local development package

## Status: PACKAGE READY — INSTALLATION PENDING

No privileged installation has been submitted or performed. Explicit human approval of the operation below is required first; then a human must approve the Mayi request in their own interactive terminal. No agent authentication, password capture, automatic Mayi approval, signing, staging, publication, deployment, or tag creation occurred.

## Artifact and source

- UI development commit: `fc289b53f63748d49129a8365e7d735fab782352`.
- Build commit: `a50aecc` (same runtime source; corrects three stale 0.4.1-8 filename/diagnostic literals in build-deb.sh).
- Version/architecture: `mayi 0.4.1-9~ui1 amd64`.
- Package: `[local-only path omitted]`.
- SHA-256: `b3fddaac840fc941952f822b5589954e28a2ee71e52c432d961f0c94b7594879`.
- Archived build input: `local-install/source.tar`; fresh source extraction and Cargo release target in a disposable Debian 11 VM child overlay. Preserved qualification VM images were backing inputs only; no original image was booted writable.

## Build and verification

Existing executor/package/build-deb.sh and TPA configuration used, not a replacement packaging implementation. Offline Rust/Cargo 1.95.0, GCC 10.2.1, binutils 2.35.2, GLIBC 2.31-13+deb11u14, libpam0g-dev 1.4.0-9+deb11u2. TPA 0.7.1~dev.20261014190140 SHA-256 `4da9418be15d2d5e212e21ff399a33519ca342522633afaed6341705765370a7`. SOURCE_DATE_EPOCH=1792195200. Build VM had restricted networking and used cached locked Cargo inputs. No host native binary was packaged.

Build and existing ABI verification PASS. Both executables require maximum GLIBC_2.30, below declared GLIBC >=2.31; detailed ELF/needed-library evidence is local-install/abi.json. This is not a repeatability claim: the candidate was built once.

Package identity and dependencies inspected. All payload entries root:root, no set-ID or group/world-writable modes, executable entry points 0755. Packaged UI Python files and service definitions match source. PAM conffile matches both source and the current host. No manual PAM edit. Full manifests and validation: local-install/package-info.txt, package-files.txt, package-validation.json.

Repeated host regressions: Rust 103+5 PASS; Python 68 PASS, 9 installed-console skips. Unprivileged Debian 11 full Rust attempt: 82 PASS / 21 FAIL, attributable to documented CAP_DAC_READ_SEARCH filesystem fixture prerequisites and ext4 socket inode reuse; pytest not installed in that guest. Retained as failures in regressions-debian11.log, not relabeled PASS. No host test capability grants or privileged test setup. Full installed Debian matrix remains unqualified.

APT simulation: only mayi upgraded, zero added/removed packages, all declared dependencies already satisfied. No network download is needed. Simulation does not guarantee installation success or reserve package locks.

## Current installation and rollback preservation

- Installed: `mayi 0.4.1-1 amd64`, install ok installed. dpkg --verify mayi reported no differences.
- Existing broker and privileged executor: active/running. PAM helper unit absent, as expected for the old architecture.
- Original package found in both APT cache and developer artifact directory; hashes match.
- Preserved rollback: `[local-only path omitted]`.
- Rollback SHA-256: `665d1154f7a0227ae93a5485c6ba493b57c18df856935e2611f8527270edb5d8`.
- Read-only installed metadata, account/group membership, service properties and public PAM conffile snapshot saved under local-install. No passwords or authentication sessions copied. Existing human memberships unchanged.

## Proposed installation — NOT executed

Do not run APT directly as a Mayi executor child: the maintainer scripts restart that same executor and broker. Instead ask Mayi to create a dedicated systemd timer/service, whose APT process runs in an independent systemd cgroup. The 15-second delay lets the scheduling command return before maintenance. Scheduling success is NOT installation success. No shell wrapper, new executable, or privilege-rule evasion is involved. If Mayi rejects this exact operation, stop and report it.

Exact proposed request:

```sh
mayi /usr/bin/systemd-run \
  --unit=mayi-ui1-local-install \
  --on-active=15s --timer-property=AccuracySec=1s \
  --property=Type=oneshot --property=RemainAfterExit=yes \
  /usr/bin/apt-get --assume-yes --no-download --no-remove install \
  '[local-only path omitted]
```

APT's --assume-yes applies only to this explicitly preapproved, simulated package plan; it is not automatic Mayi approval. No --force-* or conffile override. Human PAM occurs only in the human's own mayi-approve terminal. Recheck artifact hash, installed version, locks and simulation before submission after approval. Drain/finish pending requests first: broker restart loses pending queue/results. Maintenance may briefly stop Mayi services. The new package introduces the PAM helper and per-decision PAM authentication. No unrelated persistent service configuration is requested; the named transient install timer/service is for this operation only.

After the operation, inspect independently (not yet run against a new install):

```sh
systemctl show mayi-ui1-local-install.service -p ActiveState -p SubState -p Result -p ExecMainStatus
journalctl -u mayi-ui1-local-install.service --no-pager
dpkg-query -W -f='${Version} ${Status}\n' mayi
dpkg --verify mayi
systemctl --no-pager status mayi-broker mayi-pam-auth mayi-privileged-executor
```

Compare installed native binaries and Python UI files against extracted package bytes; confirm running executable paths and no deleted pre-upgrade processes. Authentication remains unverified until the human smoke test below.

## Interactive smoke test — pending installation and human participation

In the human approver's terminal:

```sh
before=$(stty -g)
mayi-approve
# After quitting or Ctrl-C:
test "$(stty -g)" = "$before" && printf 'terminal settings restored\n'
```

In a separate requester terminal:

```sh
mayi /usr/bin/bash -c 'printf "%s\n" "Mayi UI smoke test"'
printf 'Mayi exit status: %s\n' "$?"
```

Expected: compact bash label, interpreter warning and escaped argument preview. Space toggles details; [ and ] page; complete /usr/bin/bash and original argv remain accessible. Resize and navigate. a + Enter explicitly requests approval; follow PAM prompts yourself. Successful request prints Mayi UI smoke test and exits 0. Repeat the same harmless request, then d + Enter and all + Enter to deny; authenticate if asked; requester exits 10 with no child output. q + Enter quits without deciding; Ctrl-C cancels console input, not the broker request. Do not approve leftover requests accidentally. Verify echo/input/cursor normally afterward. Redirect requester stdout in a separate repeat to confirm no UI progress escapes there. No automated credential handling or recording of human terminal/password input.

Installed UI, real PAM success/denial, full terminal lifecycle and machine-readable smoke tests: NOT RUN yet. Existing unit/PT Y tests do not substitute for these.

## Rollback — requires separate authorization, never automatic

If Mayi is functional, the analogous explicit request is:

```sh
mayi /usr/bin/systemd-run \
  --unit=mayi-ui1-local-rollback \
  --on-active=15s --timer-property=AccuracySec=1s \
  --property=Type=oneshot --property=RemainAfterExit=yes \
  /usr/bin/apt-get --assume-yes --allow-downgrades --no-download --no-remove install \
  '[local-only path omitted]
```

First simulate the downgrade, inspect the current failure/partial-install state, and request authorization; retain logs. If Mayi itself cannot authorize, stop: a human administrator needs an independently authorized recovery terminal to run the same apt-get downgrade command. The agent must not bypass Mayi with sudo/su/pkexec or a root shell. No purge, forced conflict resolution, account deletion, or automatic cleanup. Retain the new PAM-helper unit's status and check downgrade lifecycle effects; clean up leftovers only under separately reviewed authorization. Rolling back restores the older security model, not 0.4.1-8's later fixes.

## Boundaries

Both immutable 0.4.1-8 bundle manifests and all manifested files rechecked successfully read-only. No candidate copied to releases/ or release-staging-local/. No signing, staging or publication. Installation remains pending. This is a local development test artifact, not production-ready; original UI INCONCLUSIVE qualification and documented filesystem/queue/TTL limitations remain.
