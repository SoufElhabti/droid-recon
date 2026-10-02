# Security policy

## Authorized use

droid-recon is offensive-security tooling. Use it only on applications, accounts, networks, and devices you own or have explicit authorization to assess. A tool finding is not permission to expand scope. Follow the target program's rules, rate limits, data-handling requirements, and disclosure process.

The repository must not receive real target APKs, credentials, access tokens, private application data, screenshots, logcat excerpts, traffic captures, or unpublished exploit evidence. The ignore rules cover common artifact paths, but operators remain responsible for reviewing every commit.

## Reporting a vulnerability in droid-recon

Use GitHub's private vulnerability-reporting flow from the repository Security tab when available. Include the affected version or commit, the trust boundary involved, a minimal reproduction using synthetic data, and the expected versus observed behavior. Do not attach third-party target data.

For a public issue, limit the report to non-sensitive impact and reproduction details until the maintainer confirms a private coordination channel.

## Supported versions

The current supported development line is `0.4.0.dev1` on `dev/offsec-lab-0.4.0`. Earlier snapshots remain useful as history but do not receive security fixes until their changes are incorporated into the current line.

## Evidence handling

- Treat APK contents, decompiled strings, logs, screenshots, HAR files, and pulled storage as potentially sensitive.
- Prefer synthetic canaries over real user data and record only the minimum evidence needed to establish the claim.
- Keep manifest reachability, shell observations, ordinary-UID checks, and confirmed effects as separate evidence classes.
- Redact credentials and identifiers before sharing a report. The built-in model redaction is heuristic and is not a substitute for review.
- Delete local target artifacts according to the engagement's retention policy.
