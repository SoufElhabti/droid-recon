# Publishing checklist

`0.4.0.dev1` is a development candidate. Do not tag it as stable until every required gate below has current evidence from the candidate commit.

## Automated gates

- Python 3.11, 3.12, 3.13, and 3.14 test jobs pass.
- Ruff and MyPy pass with no ignored project-wide failures.
- Statement coverage remains at or above 65%.
- The Lottie tracer passes `node --check`.
- Both sdist and wheel build from a clean checkout.
- A fresh virtual environment installs the wheel and exposes `droid-recon` and `droid-agent`.
- The wheel contains the companion Android source and does not contain local build outputs.

## Lab gates

- Run static and code analysis against a developer-owned APK using real Android SDK tools and JADX.
- Boot a clean supported emulator and record its API level, ABI, build type, and SELinux state.
- Complete one normal audit and one bounded deep audit against synthetic or emulator-owned targets.
- Confirm the ordinary-caller package has a distinct UID from the target and retains no requested permissions.
- Confirm `audit --resume` does not duplicate observations or findings.
- Exercise Frida setup and record any host/server/Android compatibility limitation without treating a failed attach as a clean target result.
- Exercise a short network capture and confirm proxy cleanup even when no traffic is observed.

## Release hygiene

- Update `pyproject.toml`, `droid_recon.__version__`, release notes, and MCP/HAR version metadata together.
- Review the complete diff for credentials, absolute private paths, target data, APKs, sessions, and generated build files.
- Create a signed or annotated prerelease tag first. Publish stable only after the prerelease artifacts pass the same smoke tests.
