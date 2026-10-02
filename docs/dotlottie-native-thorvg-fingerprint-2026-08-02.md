# dotLottie-native / ThorVG expression fingerprint — 2026-08-02

## Purpose

The Lottie static pass now recognizes a stripped or renamed LottieFiles dotLottie native
player without relying on its shared-object filename or C++ RTTI. It requires both of the
following marker families in the same ELF:

- an exact dotLottie data-load C API symbol-name marker (`dotlottie_load_animation_data` or
  `dotlottie_load_dotlottie_data`); and
- at least three ThorVG expression-runtime property names from `$bm_rt`, `propertyGroup`,
  `toComp`, and `valueAtTime`.

The entry must carry ELF magic. This same-ELF rule intentionally does not promote a lone
format string, a lone property name, a `.so`-named non-ELF entry, or markers split across
unrelated libraries into expression-engine evidence.

## Exact released-player validation

The detector was exercised against the owned Android harness APK built from the official
dotlottie-android 0.15.0 AAR:

- AAR SHA-256:
  `ef52521f4ec30710335fde01707ef2a150722509b66efa987817972477a3eee0`
- Harness APK SHA-256:
  `1e53a69352dca748624df04b67e8945dba454e32e882c9c69a0889d6272e4a05`
- APK:
  `$HOME/lottie/audit-dotlottie-native-20260802/harness/android-key-timing-poc/evidence/dotlottie-time-setter-reclaim.apk`

The report classified `dotlottie` and `dotlottie-native-thorvg-expressions` as present.
Q5 (`dotLottie`) and Q6 (`expressions`) were both `true / high`, with the four expression
markers tied to each `libdotlottie_player.so` ABI entry. A test with the dotLottie marker
in one ELF and expression strings in a second ELF remains Q6 `false`; so does a real ELF
with only two expression markers. A `.so`-named non-ELF is ignored without consuming the
native scan budget.

## Runtime observation

The built-in `lottie_tracer` also hooks the public
`com.lottiefiles.dotlottie.core.jni.DotLottiePlayer` methods
`nativeLoadAnimationData`, `nativeLoadAnimationPath`, `nativeLoadAnimation`, and
`nativeLoadDotLottieData`. It records bounded argument metadata and the Java call stack;
byte arrays are reported by length and are not copied or consumed.

Presence still establishes only deployment. A finding additionally needs a demonstrated
attacker-influenced delivery path and the affected multi-player or reload lifecycle.

## Verification

```text
.venv/bin/python -m pytest -q
167 passed

node --check src/droid_recon/frida/scripts/lottie_tracer.js
exit 0
```
