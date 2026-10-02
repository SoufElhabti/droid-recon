# Contributing

Changes should preserve the project's core evidence rule: the manifest establishes possible reachability, while a probe establishes only the observed effect under its recorded caller context.

## Development setup

```text
python -m pip install -e ".[dev]"
ruff check src tests
mypy src
python -m pytest -q --cov=droid_recon --cov-report=term --cov-fail-under=65
node --check src/droid_recon/frida/scripts/lottie_tracer.js
python -m build
```

Python 3.11 through 3.14 are supported. Device-dependent tests must fail soft or skip when their documented prerequisites are unavailable. A regression test is required for every bug fix.

## Security-test changes

- Use synthetic fixtures or developer-owned lab applications.
- Never add target APKs, secrets, sessions, screenshots, HAR files, pulled storage, or private report evidence.
- Bound file sizes, subprocess timeouts, output volume, archive processing, and network downloads.
- Do not promote a static hit or ADB-shell result to a finding without caller reachability, effect, and source-to-sink evidence.
- Device-mutating MCP operations must remain opt-in. New read-only and mutating tools need permission-policy tests.

## Pull requests

Describe the behavior changed, its trust boundary, validation performed, and remaining limitations. Keep generated artifacts out of the commit. Before requesting review, verify that the wheel installs in a clean virtual environment and that its bundled companion source remains buildable outside the installed package directory.
