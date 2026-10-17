from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "executor/package/DEBIAN"


def test_no_maintainer_script_deletes_accounts_or_groups():
    for name in ("preinst", "postinst", "prerm", "postrm"):
        script = SCRIPTS / name
        if not script.exists():
            continue
        contents = script.read_text()
        assert "deluser" not in contents
        assert "delgroup" not in contents


def test_postinst_checks_name_and_numeric_identity_collisions_explicitly():
    script = (SCRIPTS / "postinst").read_text()
    assert 'getent group "$gid"' in script
    assert 'getent passwd "$uid"' in script
    assert "Mayi identity collision:" in script
    assert "retry package configuration" in script
    assert "using existing service account" in script
    assert "using existing group" in script


def test_upgrade_retains_legacy_pam_identity_and_starts_services_in_order():
    script = (SCRIPTS / "postinst").read_text()
    assert "legacy unprivileged" not in script
    assert "deluser" not in script
    assert "account name/UID/GID do not prove package ownership" in script
    assert script.index("deb-systemd-invoke start mayi-pam-auth.service") < script.index(
        "deb-systemd-invoke start mayi-broker.service"
    )


def test_purge_never_deletes_human_or_service_accounts_by_name():
    script = (SCRIPTS / "postrm").read_text()
    assert "deluser" not in script
    assert "delgroup" not in script
    assert "Human role accounts and role groups are administrator-managed" in script


def test_postrm_removes_only_package_state_and_systemd_registration():
    script = (SCRIPTS / "postrm").read_text()
    assert '"${1:-}" = purge' in script
    assert "/var/lib/mayi-privileged-executor" in script
    assert "deb-systemd-helper purge" in script
    assert "rmdir /run/mayi/" in script
