# droid-recon — com.humanforce.mobileapp

**Triage:** INVESTIGATE — 4 third-party-reachable, browsable, grantUriPermissions, 47 native libs, 54 sink hits

## Attack surface

- Components: **30** (6 activities, 11 services, 6 receivers, 7 providers)
- Exported: **4**
- **Reachable by a third-party app or the browser: 4** ← the only ones an attacker actually has
- Flags: has_browsable, has_grant_uri

### Third-party-reachable components

| Component | Type | Reach | Guard | Issues |
|---|---|---|---|---|
| `MainActivity` | activity | browser | — | exported activity with no permission guard; BROWSABLE — reachable from a web page via an <a href> / iframe |
| `RevocationBoundService` | service | third_party_app | com.google.android.gms.auth.api.signin.permission.REVOCATION_NOTIFICATION | — |
| `ReactNativeFirebaseMessagingReceiver` | receiver | third_party_app | com.google.android.c2dm.permission.SEND | — |
| `FirebaseInstanceIdReceiver` | receiver | third_party_app | com.google.android.c2dm.permission.SEND | — |

## Code sweep

- Files scanned: 10131
- Sink hits: 367 (**54 outside bundled libraries**)
- Source hits: 113 (29 outside libraries)

## Dynamic probes

- Observations: **8** (0 flagged interesting)
- By signal: no_effect=8
- By reachability: browser=8

> Probes run as the **shell UID**, which holds `START_ANY_ACTIVITY`. A probe that succeeds against a `shell`-only component proves nothing — reachability comes from the manifest, not the exit code.

## Findings (2)

### F001 — Custom URL scheme 'humanforce://' registered with no host or path restriction

**LOW** · remote-one-click · reach: `browser` · confidence 90% · CWE-939: Improper Authorization in Handler for Custom URL Scheme

**Component:** `com.humanforce.mobileapp.MainActivity` (activity)

**Chain:**

1. Any web page or any installed app can fire humanforce://<arbitrary> at MainActivity
2. The filter declares only the scheme — unlike the https filters, which are host- and path-scoped AND carry autoVerify=true
3. The URI reaches the React Native deeplink router as untrusted input
4. TESTED: humanforce://sso-sign-in, ?url=, ?token=, ?code= and https callback params all terminated on the login screen — no authentication bypass and no URL injection was observed

**PoC:** `adb shell am start -a android.intent.action.VIEW -d 'humanforce://sso-sign-in?token=X'`

**Impact:** Hardening only, on the evidence gathered. A scheme-only filter is a strictly larger attack surface than the host-scoped App Links beside it, and any future route added to the RN router inherits unauthenticated, remotely-reachable exposure. No exploitable behaviour was demonstrated: every probe landed on the login wall.

### F002 — No certificate pinning — app traffic is fully readable and modifiable with a device-trusted CA

**MEDIUM** · local-zero-click · reach: `third_party_app` · confidence 95% · CWE-295: Improper Certificate Validation

**Component:** `com.humanforce.mobileapp` (application)

**Chain:**

1. Attacker obtains a CA in the device trust store (MDM, malicious profile, rooted/compromised device, or a compromised public CA)
2. No pinning means the app accepts it for api.humanforce.com, api-global.humanforce.com and analytics hosts
3. VERIFIED: all captured traffic decrypted cleanly with zero handshake failures
4. Attacker reads and rewrites API requests and responses, including the login POST and session tokens

**PoC:** `droid-recon net setup && droid-recon net capture com.humanforce.mobileapp --duration 30`

**Impact:** For a workforce product handling rosters, timesheets and pay data, an attacker with a trusted-CA position reads and modifies all API traffic including credentials and session tokens. Rated MEDIUM, not HIGH, because it requires the attacker to already hold a trusted-CA position — it is a defence-in-depth failure, not a directly exploitable flaw.

## Artifacts

- `attack_surface`: sessions/com.humanforce.mobileapp/attack_surface.json
- `code_report`: sessions/com.humanforce.mobileapp/code_report.json
- `observations`: sessions/com.humanforce.mobileapp/observations.jsonl
- `findings`: sessions/com.humanforce.mobileapp/findings.jsonl
- `dead_ends`: sessions/com.humanforce.mobileapp/dead-ends.md
- `screenshots`: sessions/com.humanforce.mobileapp/screenshots
- `storage`: sessions/com.humanforce.mobileapp/storage
- `log`: sessions/com.humanforce.mobileapp/session.log