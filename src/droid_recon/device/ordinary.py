"""Probe Android IPC from a separately installed, ordinary application UID.

ADB starts only the companion activity. The target IPC calls happen inside the
companion's process, without requested permissions or shell identity. Results are
correlated by a random nonce in logcat and never include provider row values.

This is reachability evidence, not proof of an exploit or target-side effect. In
particular, sendBroadcast has no delivery acknowledgement.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import tempfile
import time
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from .. import shell
from ..models import Component

COMPANION_PACKAGE = "org.droidrecon.companion"
COMPANION_ACTIVITY = f"{COMPANION_PACKAGE}/.ProbeActivity"
LOG_TAG = "DroidReconCompanion"
RESULT_PREFIX = "DR_RESULT:"
_SOURCE_PROJECT = Path(__file__).resolve().parents[3] / "android" / "companion"
_PACKAGED_PROJECT = Path(__file__).resolve().parents[1] / "assets" / "companion"
DEFAULT_PROJECT = (_PACKAGED_PROJECT if (_PACKAGED_PROJECT / "settings.gradle").is_file()
                   else _SOURCE_PROJECT)
DEFAULT_BUILD_ROOT = (
    _SOURCE_PROJECT.parents[2] / "companion-build"
    if DEFAULT_PROJECT == _SOURCE_PROJECT and (_SOURCE_PROJECT / "settings.gradle").is_file()
    else Path(tempfile.gettempdir()) / "droid-recon" / "companion-build"
)
OPERATIONS = {"activity", "deeplink", "service", "broadcast", "provider_query",
              "provider_call"}
STATUSES = {
    "accepted_by_os", "queried", "denied", "not_found",
    "dispatched_unconfirmed", "null_cursor_unconfirmed", "timeout",
    "blocked_by_platform", "invalid_request", "error",
}
_PACKAGE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
_COMPONENT = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_$][\w$]*)+$")
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
# Add exact hashes of separately shipped release APKs here. A matching package ID
# and no-permission manifest do not establish the identity of arbitrary app code.
TRUSTED_RELEASE_APK_SHA256S: frozenset[str] = frozenset({
    "3650e010fcbd6f9d20dce74cfcd1ad0ec8660b63fe34f18f70c08fae15e5fc39",
    "0f180ca373830769fd9a50a240e00da575148ca2aefc6248e6dfdbd4057823bf",
})
_TRUSTED_SOURCE_BUILD_SHA256S: set[str] = set()

Operation = Literal["activity", "deeplink", "service", "broadcast", "provider_query",
                    "provider_call"]


@dataclass(frozen=True)
class ProbeRequest:
    operation: Operation
    target_package: str
    component: str | None = None
    uri: str | None = None
    action: str | None = None
    method: str | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def payload(self) -> dict:
        if self.operation not in OPERATIONS:
            raise ValueError(f"unsupported ordinary probe: {self.operation}")
        if not _PACKAGE.fullmatch(self.target_package):
            raise ValueError("invalid target package")
        if not re.fullmatch(r"[0-9a-f]{32}", self.id):
            raise ValueError("request id must be 32 lower-case hex characters")
        if self.operation in {"activity", "service", "broadcast"}:
            if not self.component or not _COMPONENT.fullmatch(self.component):
                raise ValueError("a fully qualified component is required")
        if self.operation in {"deeplink", "provider_query", "provider_call"}:
            if not self.uri or len(self.uri) > 4096:
                raise ValueError("a bounded URI is required")
            parts = urlsplit(self.uri)
            if not parts.scheme:
                raise ValueError("URI must have a scheme")
            if self.operation in {"provider_query", "provider_call"} and \
                    (parts.scheme != "content" or not parts.netloc):
                raise ValueError("provider probe requires content://authority URI")
        if self.action is not None and len(self.action) > 4096:
            raise ValueError("action is too long")
        if self.operation == "provider_call":
            if not self.method or len(self.method) > 256 or any(
                    ord(char) < 32 or ord(char) == 127 for char in self.method):
                raise ValueError("provider call requires a bounded method name")
        elif self.method is not None:
            raise ValueError("method is only valid for an explicit provider call")
        payload = {"id": self.id, "operation": self.operation,
                   "target_package": self.target_package}
        for key in ("component", "uri", "action", "method"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        return payload


@dataclass
class CompanionBuild:
    status: Literal["built", "unavailable", "failed"]
    apk: Path | None = None
    message: str = ""


@dataclass
class CompanionInstall:
    status: Literal["installed", "failed"]
    message: str = ""
    serial: str | None = None
    verified_build: bool = False


@dataclass
class OrdinaryResult:
    request_id: str
    operation: str
    target_package: str
    status: str
    caller_package: str | None = None
    caller_uid: int | None = None
    verified_ordinary_uid: bool = False
    detail: dict = field(default_factory=dict)

    @property
    def accessible(self) -> bool | None:
        """OS access only; never interpret this as a demonstrated vulnerability."""
        if not self.verified_ordinary_uid:
            return None
        if self.status in {"accepted_by_os", "queried"}:
            return True
        if self.status in {"denied", "not_found"}:
            return False
        return None

    def to_dict(self) -> dict:
        return {**asdict(self), "accessible": self.accessible,
                "evidence_status": ("OBSERVED_ORDINARY_UID" if self.verified_ordinary_uid
                                    else "INCONCLUSIVE")}


def request_for_component(
    package: str, component: Component, *, operation: Operation | None = None,
    uri: str | None = None, action: str | None = None, method: str | None = None,
) -> ProbeRequest:
    """Build a request from a manifest component.

    Provider calls require an explicit operation and recovered method name because
    a target-defined call method may have side effects.
    """
    if operation is None:
        operation = {
            "activity": "activity", "activity-alias": "activity",
            "service": "service", "receiver": "broadcast", "provider": "provider_query",
        }[component.type]
    if operation in {"provider_query", "provider_call"} and component.type != "provider":
        raise ValueError("provider probes require a provider component")
    if operation in {"provider_query", "provider_call"} and uri is None:
        if not component.authorities:
            raise ValueError("provider has no authority; pass a URI explicitly")
        uri = f"content://{component.authorities[0]}"
    if operation == "deeplink" and uri is None:
        links = component.deeplinks()
        if not links:
            raise ValueError("component has no manifest deep link; pass a URI explicitly")
        uri = links[0]
    if operation == "broadcast" and action is None:
        action = next((a for f in component.intent_filters for a in f.actions), None)
    return ProbeRequest(operation=operation, target_package=package,
                        component=component.name, uri=uri, action=action, method=method)


def _apk_sha256(apk: Path) -> str:
    digest = hashlib.sha256()
    with apk.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remember_source_build(apk: Path, project: Path) -> None:
    if project.resolve() == DEFAULT_PROJECT.resolve():
        _TRUSTED_SOURCE_BUILD_SHA256S.add(_apk_sha256(apk))


def _validate_companion_manifest(xml_text: str) -> str | None:
    """Return a reason to refuse an APK, or None for a permission-free manifest."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "companion APK manifest could not be parsed"
    if root.tag != "manifest" or root.get("package") != COMPANION_PACKAGE:
        return f"companion APK must declare package {COMPANION_PACKAGE}"
    if root.get(f"{_ANDROID_NS}sharedUserId") is not None:
        return "companion APK must not declare a shared user ID"
    if any(child.tag.split("}")[-1].startswith("uses-permission") for child in root):
        return "companion APK must request no Android permissions"
    return None


def _inspect_companion_apk(apk: Path) -> tuple[str | None, str | None]:
    """Check APK manifest safety and return (failure reason, SHA-256)."""
    if not apk.is_file():
        return f"companion APK not found: {apk}", None
    if not zipfile.is_zipfile(apk):
        return "companion APK is not a valid ZIP archive", None
    digest = _apk_sha256(apk)
    # An exact release hash already attests to the manifest inspected when the
    # release was selected. This also permits a trusted prebuilt with only adb.
    if digest in TRUSTED_RELEASE_APK_SHA256S:
        return None, digest
    from ..static import manifest

    try:
        xml_text = manifest.dump_manifest_xml(apk, timeout=30)
    except (OSError, ValueError) as exc:
        return f"cannot verify companion APK manifest: {exc}", None
    failure = _validate_companion_manifest(xml_text)
    if failure:
        return failure, None
    return None, digest


def build_companion(project: Path = DEFAULT_PROJECT, *, gradle: str | None = None,
                    build_root: Path = DEFAULT_BUILD_ROOT,
                    timeout: int = 300) -> CompanionBuild:
    """Build with Gradle, or directly with the installed SDK build tools.

    The direct route is fully offline and keeps all generated files outside the
    Android source directory. It is useful on workstations with an SDK but no Gradle.
    """
    project = Path(project)
    if not (project / "settings.gradle").is_file():
        return CompanionBuild("unavailable", message=f"companion source not found: {project}")
    tool = gradle or shell.which("gradle")
    if tool:
        proc = shell.run([tool, ":app:assembleDebug", "--no-daemon"],
                         timeout=timeout, cwd=project)
        apk = project / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
        if proc.ok and apk.is_file():
            _remember_source_build(apk, project)
            return CompanionBuild("built", apk=apk, message="companion APK built with Gradle")
    built = _build_with_sdk(project, Path(build_root), timeout=timeout)
    if built.status == "built" and built.apk is not None:
        _remember_source_build(built.apk, project)
    return built


def _build_with_sdk(project: Path, build_root: Path, *, timeout: int) -> CompanionBuild:
    sdk = shell.android_home()
    javac = shell.which("javac")
    aapt2 = shell.aapt2_path()
    if sdk is None or javac is None or aapt2 is None:
        return CompanionBuild("unavailable", message="Android SDK, aapt2, or javac is missing")
    platforms = sorted((sdk / "platforms").glob("android-*"), reverse=True)
    android_jar = next((p / "android.jar" for p in platforms
                        if (p / "android.jar").is_file()), None)
    if android_jar is None:
        return CompanionBuild("unavailable", message="no Android platform android.jar found")
    tools_dir = Path(aapt2).parent
    java = Path(javac).with_name("java.exe" if Path(javac).suffix.lower() == ".exe" else "java")
    keytool = Path(javac).with_name("keytool.exe" if Path(javac).suffix.lower() == ".exe" else "keytool")
    d8_jar = tools_dir / "lib" / "d8.jar"
    signer_jar = tools_dir / "lib" / "apksigner.jar"
    zipalign = tools_dir / ("zipalign.exe" if Path(aapt2).suffix == ".exe" else "zipalign")
    needed = [java, keytool, d8_jar, signer_jar, zipalign]
    if any(not path.is_file() for path in needed):
        return CompanionBuild("unavailable", message="SDK build tools or JDK utilities are incomplete")

    source_root = project / "app" / "src" / "main"
    manifest = source_root / "AndroidManifest.xml"
    sources = sorted((source_root / "java").rglob("*.java"))
    if not manifest.is_file() or not sources:
        return CompanionBuild("unavailable", message="companion manifest or Java source is missing")
    build_root.mkdir(parents=True, exist_ok=True)
    classes = build_root / "classes"
    dex = build_root / "dex"
    classes.mkdir(exist_ok=True)
    dex.mkdir(exist_ok=True)
    linked = build_root / "linked.apk"
    aligned = build_root / "aligned.apk"
    output = build_root / "droid-recon-companion.apk"
    keystore = build_root / "debug.keystore"
    # Keep a stable signing identity for reinstall, but never reuse stale bytecode.
    for old in (*classes.rglob("*.class"), *dex.glob("*.dex"), linked, aligned, output):
        old.unlink(missing_ok=True)

    commands = [
        [str(aapt2), "link", "-o", str(linked), "--manifest", str(manifest),
         "-I", str(android_jar), "--min-sdk-version", "26",
         "--target-sdk-version", "35", "--version-code", "1", "--version-name", "1.0"],
        [str(javac), "-source", "8", "-target", "8", "-classpath", str(android_jar),
         "-d", str(classes), *(str(source) for source in sources)],
    ]
    for argv in commands:
        proc = shell.run(argv, timeout=timeout)
        if not proc.ok:
            return CompanionBuild("failed", message=(proc.stderr or proc.stdout)[-1200:])
    class_files = sorted(classes.rglob("*.class"))
    if not class_files:
        return CompanionBuild("failed", message="javac produced no class files")
    proc = shell.run(
        [str(java), "-cp", str(d8_jar), "com.android.tools.r8.D8",
         "--min-api", "26", "--lib", str(android_jar), "--output", str(dex),
         *(str(path) for path in class_files)], timeout=timeout,
    )
    if not proc.ok or not (dex / "classes.dex").is_file():
        return CompanionBuild("failed", message=(proc.stderr or proc.stdout)[-1200:]
                              or "d8 produced no classes.dex")
    with zipfile.ZipFile(linked, "a") as archive:
        archive.write(dex / "classes.dex", "classes.dex")
    proc = shell.run([str(zipalign), "-f", "-p", "4", str(linked), str(aligned)],
                     timeout=timeout)
    if not proc.ok:
        return CompanionBuild("failed", message=(proc.stderr or proc.stdout)[-1200:])
    if not keystore.is_file():
        proc = shell.run(
            [str(keytool), "-genkeypair", "-noprompt", "-alias", "androiddebugkey",
             "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650",
             "-keystore", str(keystore), "-storepass", "android", "-keypass", "android",
             "-dname", "CN=Android Debug,O=Android,C=US"], timeout=timeout,
        )
        if not proc.ok:
            return CompanionBuild("failed", message=(proc.stderr or proc.stdout)[-1200:])
    proc = shell.run(
        [str(java), "-jar", str(signer_jar), "sign", "--ks", str(keystore),
         "--ks-key-alias", "androiddebugkey", "--ks-pass", "pass:android",
         "--key-pass", "pass:android", "--out", str(output), str(aligned)], timeout=timeout,
    )
    if not proc.ok or not output.is_file():
        return CompanionBuild("failed", message=(proc.stderr or proc.stdout)[-1200:]
                              or "apksigner produced no APK")
    verified = shell.run([str(java), "-jar", str(signer_jar), "verify", str(output)],
                         timeout=timeout)
    if not verified.ok:
        return CompanionBuild("failed", message="APK signature verification failed: "
                              + (verified.stderr or verified.stdout)[-800:])
    return CompanionBuild("built", apk=output,
                          message="companion APK built and signature verified with SDK tools")


def _emulator_serial(serial: str | None) -> str:
    if serial is None:
        devices = shell.devices()
        if len(devices) != 1:
            raise ValueError("specify one emulator serial when zero or multiple devices are attached")
        serial = devices[0]
    # A physical device is intentionally outside this bounded test harness.
    proc = shell.adb_shell(["getprop", "ro.kernel.qemu"], serial=serial, timeout=10)
    if not proc.ok or proc.stdout.strip() != "1":
        raise ValueError(f"device {serial} is not an Android emulator")
    return serial


def install_companion(apk: Path, serial: str | None = None) -> CompanionInstall:
    """Inspect before install; only a known build can yield verified evidence."""
    serial = _emulator_serial(serial)
    apk = Path(apk)
    failure, digest = _inspect_companion_apk(apk)
    if failure:
        return CompanionInstall("failed", failure, serial)
    verified_build = digest in (TRUSTED_RELEASE_APK_SHA256S |
                                _TRUSTED_SOURCE_BUILD_SHA256S)
    proc = shell.adb("install", "-r", str(apk), serial=serial, timeout=120)
    message = (proc.stdout + proc.stderr).strip()[-1200:]
    if not proc.ok or "Success" not in message:
        return CompanionInstall("failed", message or f"adb install rc={proc.rc}", serial)
    check = shell.adb_shell(["pm", "path", COMPANION_PACKAGE], serial=serial, timeout=15)
    if not check.ok or "package:" not in check.stdout:
        return CompanionInstall("failed", "installed APK did not expose expected package", serial)
    return CompanionInstall(
        "installed",
        ("verified companion build installed without requested permissions"
         if verified_build else
         "custom companion installed without requested permissions; source unverified"),
        serial, verified_build=verified_build,
    )


def _parse_result(log_text: str, request: ProbeRequest, *,
                  trusted_source: bool = False) -> OrdinaryResult | None:
    for line in reversed(log_text.splitlines()):
        if RESULT_PREFIX not in line:
            continue
        try:
            obj = json.loads(line.split(RESULT_PREFIX, 1)[1])
        except (ValueError, TypeError):
            continue
        if obj.get("id") != request.id or obj.get("operation") != request.operation:
            continue
        uid = obj.get("caller_uid")
        try:
            uid = int(uid)
        except (ValueError, TypeError):
            uid = None
        package = obj.get("caller_package")
        status = obj.get("status", "error")
        if status not in STATUSES:
            status = "error"
        detail = {key: obj[key] for key in ("has_row", "column_count", "has_result",
                                            "exception") if key in obj}
        if not trusted_source:
            detail["reason"] = "unverified_companion_build"
        return OrdinaryResult(
            request.id, request.operation, request.target_package, status,
            caller_package=package, caller_uid=uid,
            verified_ordinary_uid=(trusted_source and package == COMPANION_PACKAGE
                                   and uid is not None and uid >= 10000),
            detail=detail,
        )
    return None


def run_probe(request: ProbeRequest, *, serial: str | None = None,
              timeout: float = 20.0, poll_interval: float = 0.3,
              trusted_source: bool = False) -> OrdinaryResult:
    """Run one probe; only a verified build may produce verified UID evidence.

    Pass ``trusted_source=installed.verified_build`` after installing the APK.
    Arbitrary prebuilt app code can fabricate log lines even with no permissions.
    """
    payload = request.payload()  # validate before touching the device
    if timeout <= 0 or timeout > 60:
        raise ValueError("timeout must be in (0, 60] seconds")
    serial = _emulator_serial(serial)
    installed = shell.adb_shell(["pm", "path", COMPANION_PACKAGE], serial=serial, timeout=15)
    if not installed.ok or "package:" not in installed.stdout:
        return OrdinaryResult(request.id, request.operation, request.target_package,
                              "blocked_by_platform", detail={"reason": "companion_not_installed"})

    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    # A prior hung Binder call cannot contaminate this run. This is setup by shell;
    # the target IPC itself still originates from the newly launched app process.
    shell.adb_shell(["am", "force-stop", COMPANION_PACKAGE], serial=serial, timeout=10)
    launched = shell.adb_shell(
        ["am", "start", "-W", "-n", COMPANION_ACTIVITY, "--es", "payload", encoded],
        serial=serial, timeout=20,
    )
    if not launched.ok or "error" in (launched.stdout + launched.stderr).lower():
        return OrdinaryResult(request.id, request.operation, request.target_package,
                              "blocked_by_platform",
                              detail={"reason": "companion_launch_failed",
                                      "launch_output": (launched.stdout + launched.stderr)[-400:]})

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        log = shell.adb("logcat", "-d", "-v", "brief", "-s", f"{LOG_TAG}:I", "*:S",
                        serial=serial, timeout=5)
        if log.ok:
            result = _parse_result(log.stdout, request, trusted_source=trusted_source)
            if result is not None:
                return result
        time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))
    return OrdinaryResult(request.id, request.operation, request.target_package,
                          "timeout", detail={"reason": "no_correlated_companion_result"})
