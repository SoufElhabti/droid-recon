# Third-party attribution

`droid-recon` has **zero third-party Python runtime dependencies**. The only vendored
third-party material is a Frida script.

## `src/droid_recon/frida/scripts/ssl_unpin.js`

Universal Android SSL-unpinning script. Not original work — it combines and extends
publicly published Frida scripts, per its own header:

- <https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/>
- <https://codeshare.frida.re/@avltree9798/universal-android-ssl-pinning-bypass/>
- <https://pastebin.com/TVJD63uM>

These are community scripts published on Frida CodeShare. Retained verbatim so upstream
fixes can be diffed in. If you redistribute this project, keep this attribution.

`crypto_logger.js` and `webview_hooks.js` are original to this project.

## Tools invoked as subprocesses (not bundled, not linked)

`adb`, `emulator`, `avdmanager`, `apkanalyzer`, `aapt2` (Android SDK, Apache-2.0);
`jadx` (Apache-2.0); `apktool` (Apache-2.0); `frida` / `frida-server` (wxWindows Library
Licence). These are located on `PATH` at runtime and shelled out to — none of their code
is included here.

## Prior art

The static analysis ports patterns from the author's own `android-privesc-hunt`
(sink/source regex tables, findings schema, triage-verdict shape).

## Not used

The original spec (`prompt.md`) proposed building on `mobilerun` (MIT). That dependency
was **dropped entirely** — no mobilerun code is present, so no MIT attribution is owed.
See `CLAUDE.md` § "Where the spec was wrong" for the reasoning.
