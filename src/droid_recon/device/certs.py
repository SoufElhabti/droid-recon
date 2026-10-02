"""System CA injection on Android 14 (API 34).

The spec's approach (prompt.md:119-131) — push a cert to `/system/etc/security/cacerts`
and reboot — does not work on API 34. Verified on this device: the live trust store is
`/apex/com.android.conscrypt/cacerts`, a read-only ext4 mount from the conscrypt APEX.
Writing to `/system/etc/security/cacerts` changes a directory nothing reads.

The technique that DOES work (same idea as HTTP Toolkit / Magisk's cert modules):

  1. Copy the existing 134 APEX certs to a staging dir.
  2. Mount a tmpfs OVER `/apex/com.android.conscrypt/cacerts`.
  3. Restore the originals into the tmpfs, plus our CA.
  4. Fix ownership/mode/SELinux context — conscrypt rejects wrongly-labelled files.
  5. Propagate into the mount namespace of **zygote** (so every app forked afterwards
     inherits it) and of each already-running target process.

Step 5 is the part people miss. A bind-mount in the shell's namespace is invisible to
apps: they live in zygote's namespace. Without nsenter you get a trust store that looks
correct from `adb shell` and changes nothing for the app under test.

This is all destroyed on reboot, which is fine — it is a per-session operation.
"""

from __future__ import annotations

import re
from pathlib import Path

from .. import shell
from ..log import ok, say, warn

APEX_CACERTS = "/apex/com.android.conscrypt/cacerts"
LEGACY_CACERTS = "/system/etc/security/cacerts"
STAGING = "/data/local/tmp/dr-cacerts"
REMOTE_CERT = "/data/local/tmp/dr-ca.pem"

# The SELinux label Conscrypt requires on trust-store entries.
#
# Getting this wrong is the single most likely reason a "successful" injection still
# yields `CertPathValidatorException: Trust anchor for certification path not found`.
# Files created in a fresh tmpfs inherit `appdomain_tmpfs`, which Conscrypt will not
# read as a trust anchor — the certificate is present, readable, correctly named and
# correctly hashed, and still ignored. Verified on this device by diffing the label of
# an injected cert against a pristine one in /apex/com.android.conscrypt@<ver>/cacerts.
CACERT_SELINUX_LABEL = "u:object_r:system_security_cacerts_file:s0"


def cert_hash(pem_path: Path) -> str | None:
    """OpenSSL subject_hash_old — the filename Android's trust store expects."""
    proc = shell.run(
        ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(pem_path)],
        timeout=30,
    )
    if not proc.ok:
        warn(f"openssl failed on {pem_path}: {proc.stderr.strip()[:120]}")
        return None
    first = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""
    return first if re.fullmatch(r"[0-9a-f]{8}", first) else None


def is_installed(pem_path: Path, serial: str | None = None) -> bool:
    h = cert_hash(pem_path)
    if not h:
        return False
    proc = shell.adb_shell(["ls", f"{APEX_CACERTS}/{h}.0"], serial=serial, timeout=20)
    return proc.rc == 0


def _running_app_pids(serial: str | None) -> list[str]:
    """Pids worth entering: zygote (template for future apps) + live app processes."""
    pids: list[str] = []
    for name in ("zygote64", "zygote"):
        proc = shell.adb_shell(["pidof", name], serial=serial, timeout=20)
        pids += proc.stdout.split()

    # Any process whose cmdline looks like an app package, so already-running targets
    # pick the new store up without a restart.
    ps = shell.adb_shell(["ps", "-A", "-o", "PID,NAME"], serial=serial, timeout=30)
    for line in ps.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and "." in parts[1] and not parts[1].startswith("/"):
            pids.append(parts[0])

    seen: set[str] = set()
    out: list[str] = []
    for pid in pids:
        if pid.isdigit() and pid not in seen:
            seen.add(pid)
            out.append(pid)
    return out


def install_system_ca(pem_path: Path, serial: str | None = None) -> tuple[bool, str]:
    """Inject `pem_path` into the live system trust store. Returns (ok, message)."""
    if not pem_path.exists():
        return False, f"CA file not found: {pem_path}"

    who = shell.adb_shell(["whoami"], serial=serial, timeout=15).stdout.strip()
    if who != "root":
        return False, "device is not rooted (`adb root` first) — cannot modify the trust store"

    h = cert_hash(pem_path)
    if not h:
        return False, "could not compute the certificate subject hash (is openssl present?)"

    # Present is not the same as trusted: a cert with the wrong SELinux label is
    # readable, correctly hashed, and silently ignored by Conscrypt. Verify the label
    # before short-circuiting, or a stale bad overlay looks like success forever.
    if is_installed(pem_path, serial) and label_of(f"{APEX_CACERTS}/{h}.0", serial) == CACERT_SELINUX_LABEL:
        ok(f"CA {h}.0 already present and correctly labelled")
        return True, f"already installed as {h}.0"
    if is_installed(pem_path, serial):
        warn(f"CA {h}.0 present but mislabelled — rebuilding the overlay")
        remove_system_ca(serial)

    push = shell.adb("push", str(pem_path), REMOTE_CERT, serial=serial, timeout=60)
    if not push.ok:
        return False, f"push failed: {push.stderr.strip()[:160]}"

    say("certs", f"injecting CA {h}.0 into {APEX_CACERTS} (tmpfs overlay)")

    # Steps 1-4, in one shell so the tmpfs and the copy-back cannot be interleaved.
    setup = f"""
set -e
rm -rf {STAGING}; mkdir -p {STAGING}
cp {APEX_CACERTS}/* {STAGING}/ 2>/dev/null || cp {LEGACY_CACERTS}/* {STAGING}/
cp {REMOTE_CERT} {STAGING}/{h}.0
chown root:root {STAGING}/*
chmod 644 {STAGING}/*
mount -t tmpfs tmpfs {APEX_CACERTS}
cp {STAGING}/* {APEX_CACERTS}/
chown root:root {APEX_CACERTS}/*
chmod 644 {APEX_CACERTS}/*
chcon {CACERT_SELINUX_LABEL} {APEX_CACERTS}/* 2>/dev/null || true
ls {APEX_CACERTS} | wc -l
"""
    res = shell.adb_script(setup, serial=serial, timeout=180)
    if res.rc != 0:
        return False, f"tmpfs overlay failed: {(res.stderr or res.stdout).strip()[:300]}"

    count = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else "?"

    # Step 5 — the part that actually makes apps see it.
    entered, failed = _propagate_to_namespaces(h, serial)

    # Also refresh the legacy path; a few libraries still read it directly.
    shell.adb_script(f"cp {REMOTE_CERT} {LEGACY_CACERTS}/{h}.0 2>/dev/null || true",
                     serial=serial, timeout=60)

    if not is_installed(pem_path, serial):
        return False, "overlay applied but the certificate is not visible afterwards"

    ok(f"CA installed as {h}.0 ({count} certs in store, propagated to {entered} namespace(s))")
    msg = f"installed {h}.0; {count} certs; {entered} namespaces entered"
    if failed:
        msg += f"; {failed} namespace(s) refused (already-running apps may not trust it)"
    return True, msg


def _propagate_to_namespaces(cert_hash_value: str, serial: str | None) -> tuple[int, int]:
    """Replicate the overlay inside each process's mount namespace.

    Apps do not share the shell's mount namespace — they inherit zygote's. Without this
    the trust store looks patched from `adb shell` and is unchanged for every app.
    """
    pids = _running_app_pids(serial)
    if not pids:
        warn("no zygote/app pids found — new apps may not see the CA")
        return 0, 0

    entered = failed = 0
    for pid in pids:
        # chcon MUST be inside the namespace too. Relabelling in the shell's namespace
        # does nothing for the app's private tmpfs mount — that omission is what made
        # an otherwise-correct injection still fail trust-anchor validation.
        cmd = (
            f"nsenter --mount=/proc/{pid}/ns/mnt -- "
            f"/bin/sh -c 'mount -t tmpfs tmpfs {APEX_CACERTS} && "
            f"cp {STAGING}/* {APEX_CACERTS}/ && "
            f"chown root:root {APEX_CACERTS}/* && chmod 644 {APEX_CACERTS}/* && "
            f"chcon {CACERT_SELINUX_LABEL} {APEX_CACERTS}/*'"
        )
        res = shell.adb_script(cmd, serial=serial, timeout=45)
        if res.rc == 0:
            entered += 1
        else:
            failed += 1
    say("certs", f"mount namespaces: {entered} patched, {failed} refused")
    return entered, failed


def label_of(path: str, serial: str | None = None) -> str:
    """SELinux context of a file on device, or "" if it cannot be read."""
    res = shell.adb_script(f"ls -Z {path} 2>/dev/null | head -1", serial=serial, timeout=20)
    parts = res.stdout.split()
    return parts[0] if parts and parts[0].startswith("u:object_r:") else ""


def remove_system_ca(serial: str | None = None) -> bool:
    """Drop the tmpfs overlay everywhere, restoring the pristine APEX store.

    Must unmount inside every namespace as well as the shell's. Unmounting only the
    shell's leaves 60+ app namespaces holding a stale overlay, which then looks absent
    from `adb shell` while still shadowing the real store for every running app.
    Stacked mounts are possible, so unmount repeatedly until it fails.
    """
    inner = (
        f"for i in 1 2 3 4 5; do umount {APEX_CACERTS} 2>/dev/null || break; done"
    )
    for pid in _running_app_pids(serial):
        shell.adb_script(
            f"nsenter --mount=/proc/{pid}/ns/mnt -- /bin/sh -c '{inner}'",
            serial=serial, timeout=30,
        )
    res = shell.adb_script(f"{inner}; rm -rf {STAGING} {REMOTE_CERT}", serial=serial, timeout=60)
    return res.rc == 0


def install_user_ca(pem_path: Path, serial: str | None = None) -> tuple[bool, str]:
    """Fallback: the user trust store.

    Only helps for apps that opt in via `networkSecurityConfig` (`trust-anchors
    src="user"`) or that target API < 24. Worth doing anyway — it is cheap, and
    `static` already tells us which apps trust user CAs.
    """
    h = cert_hash(pem_path)
    if not h:
        return False, "could not hash certificate"
    dest = f"/data/misc/user/0/cacerts-added/{h}.0"
    shell.adb_shell(["mkdir", "-p", "/data/misc/user/0/cacerts-added"], serial=serial, timeout=20)
    push = shell.adb("push", str(pem_path), dest, serial=serial, timeout=60)
    if not push.ok:
        return False, push.stderr.strip()[:160]
    shell.adb_shell(["chmod", "644", dest], serial=serial, timeout=20)
    shell.adb_shell(["chown", "system:system", dest], serial=serial, timeout=20)
    return True, f"user CA installed as {h}.0"


def trust_status(serial: str | None = None) -> dict:
    """What the trust store looks like right now — for the report's methodology section."""
    apex = shell.adb_script(f"ls {APEX_CACERTS} 2>/dev/null | wc -l",
                            serial=serial, timeout=20).stdout.strip()
    mounted = shell.adb_script(f"mount | grep -c 'tmpfs on {APEX_CACERTS}'",
                               serial=serial, timeout=20).stdout.strip()
    user = shell.adb_script("ls /data/misc/user/0/cacerts-added 2>/dev/null | wc -l",
                            serial=serial, timeout=20).stdout.strip()
    return {
        "apex_cert_count": apex,
        "tmpfs_overlay_active": mounted not in ("", "0"),
        "user_ca_count": user,
        "store_path": APEX_CACERTS,
    }
