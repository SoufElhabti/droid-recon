# Local Android Surface-C static scan — 2026-08-02

## Result

No locally available APK or extracted Android source tree statically demonstrates the critical Surface-C chain:

`lottie-web/bodymovin engine` + `WebView` + `addJavascriptInterface` + `attacker-controlled animation or URL` in one reachable flow.

This is a static negative result, not proof that every runtime path is safe. No production interaction, upload, or dynamic delivery test was performed.

## APK coverage

- Discovery root: `/Users/soufianeelhabti`
- Discovery command shape: `rg --files --hidden -g '*.apk' /Users/soufianeelhabti`
- APK paths found: **280**
- Valid ZIP/APKs scanned: **278**
- Archive entries inspected: **80,731**
- Total uncompressed archive bytes observed by the detector: **556,732,756**
- Web/text-like entries independently content-scanned (`js`, `mjs`, `html`, `htm`, `bundle`, `json`, `txt`, `xml`, `css`, `map`): **31,805 entries / 472,117,790 bytes**
- `lottie-web`/bodymovin engine markers in those entries: **0**
- Archive entry names matching `lottie-web`, `bodymovin`, `lottie.js`, `lottie.min.js`, or `lottie-player`: **0**
- Detector Q3 (`lottie-web/bodymovin in WebView assets`): **false / not_found**
- Detector Q10 (`animation payload reachable by bridge/URL delivery`): **false / not_demonstrated**

The two discovered paths that were not APK ZIPs are small invalid files:

- `/Users/soufianeelhabti/web-hunt/visa/apk/com.fraedom.expenses.apk` — 5,840 bytes
- `/Users/soufianeelhabti/web-hunt/visa/apk/com.visa.spendmanagement.apk` — 5,852 bytes

The only extracted-source `bodymovin` matches were Lottie-Android parser warning text, not the JavaScript renderer. Examples:

- `/Users/soufianeelhabti/dba_analysis/java/sources/com/airbnb/lottie/parser/moshi/JsonUtf8Reader.java:79`
- `/Users/soufianeelhabti/dba_analysis/java/sources/p5/e.java:71`
- `/Users/soufianeelhabti/Downloads/lolsj/resources/lib/arm64-v8a/libapp_strings.txt:25689`
- `/Users/soufianeelhabti/kuaishou_audit/secrets_sweep/dex_strings.txt:605288`

## ThorVG / dotlottie-rs prioritization

Native and bytecode/bundle artifacts were separately searched for `ThorVG`, `LottiePathSet`, `LottieLoader`, `LottieBuilder`, `LottieExpression`, `tvg::Animation`, `tvgLottie`, `dotlottie-rs`, `dotlottie_rs`, `lottieexpressions`, `$bm_mod`, and the known crash-shape primitives.

- Native libraries: **955 `.so` occurrences**, **624 unique blobs**, **940,439,444 uncompressed bytes**
- DEX/Hermes artifacts: **155 occurrences**, **110 unique blobs**, **792,988,117 bytes**
- ThorVG or dotlottie-rs engine evidence: **0**
- `LottiePathSet` evidence: **0**
- Exact `$bm_mod` occurrence: **0**
- Exact malicious expression `x:"$bm_rt=thisLayer;"`: **0**

`dotlottie` format or React-Native prop names were not treated as proof of the dotlottie-rs/ThorVG renderer. In particular, Discord's `libappmodules.so` contains React-Native codegen names such as `sourceDotLottieURI`; its actual sticker native library `libdsti.so` exposes rlottie symbols. No ThorVG-specific marker was found in either.

There were **55 `.lottie` archive occurrences / 19 unique assets**:

- 18 unique generated Discord resources, repeated in duplicate APK copies
- `/Users/soufianeelhabti/base.apk:res/-l.lottie` (Epic Games Portal)

Only these two unique Discord `.lottie` resources contained expression fields, with 24 ordinary bundled expressions apiece:

- `/Users/soufianeelhabti/lottie/discord-native-current/base.apk:res/raw/design_components_lottieicon_native_generated_lotties_spendearnorbs.lottie`
- `/Users/soufianeelhabti/lottie/discord-native-current/base.apk:res/raw/design_components_lottieicon_native_generated_lotties_spendearnorbslighttheme.lottie`

They are local generated assets. Neither contains `$bm_mod` or the supplied `thisLayer` path-property payload, and no remote/untrusted delivery to a ThorVG renderer was found.

## Ranked near misses

These are not confirmed Surface-C candidates.

### 1. Discord — remote animation delivery proven, but wrong renderer and no lottie-web

APK set:

- `/Users/soufianeelhabti/lottie/discord-native-current/base.apk`
- `/Users/soufianeelhabti/lottie/discord-native-current/split_config.arm64_v8a.apk`

Extracted source:

- `/Users/soufianeelhabti/.cache/droid-recon/jadx/3ffb2120f2854261/sources`
- `/Users/soufianeelhabti/.cache/droid-recon/res/3ffb2120f2854261`

Evidence:

- A serialized sticker model reaches `StickerLottieViewHolder.bind` and passes `sticker.url`/`sticker.asset` into `StickerView.asLottie`: `.../com/discord/chat/presentation/message/viewholder/StickerLottieViewHolder.java:35-43`.
- `StickerView.asLottie` constructs the rlottie configuration: `.../com/discord/sticker/StickerView.java:80-97`.
- `FileDownloader` retrieves `config.url` as `<asset>.json`: `.../com/discord/sticker/sticker_types/RLottieImageView.java:284-287`.
- The completed file reaches native `RLottieDrawable`: `.../com/discord/sticker/sticker_types/RLottieImageView.java:330-334` and `.../com/discord/rlottie/RLottieImageView.java:218-230`.
- A separate React-Native WebView enables `addJavascriptInterface(..., "ReactNativeWebView")`: `.../com/reactnativecommunity/webview/j.java:158-170`.
- Generic lottie-react-native code accepts `sourceJson`, local files, and non-file `sourceDotLottieURI` URLs: `.../k4/i.java:126-175`.

Why it does not qualify:

- The proven remote sticker path terminates in **rlottie**, not lottie-web or ThorVG.
- Hermes analysis shows sticker URLs are assembled from Discord sticker/CDN endpoints and sticker IDs; no arbitrary caller-provided URL was established.
- The WebView bridge is a separate subsystem; no bridge-to-animation flow was found.
- Generated React-Native dotLottie icon usages resolve bundled resources. Generic URL support is library capability only.
- No externally supplied image/font/text delegate was found. The Java manager's font delegate is an internal installed delegate.

Hermes evidence was disassembled from:

- `/Users/soufianeelhabti/lottie/discord-native-current/base.apk:assets/index.android.bundle` — 69,619,414 bytes
- Source-module strings include `components_native/common/LottieAnimationView.tsx`, `modules/stickers/native/NativeLottieView.tsx`, `transformSticker.tsx`, and `StickersUtils.tsx`.

### 2. Kuaishou/Kwai audit tree — bridge and expression assets, but source-only/mixed provenance

Source/audit tree:

- `/Users/soufianeelhabti/kuaishou_audit`

Relevant assets/strings:

- `/Users/soufianeelhabti/kuaishou_audit/extracted/res/e/z.json`
- `/Users/soufianeelhabti/kuaishou_audit/extracted/res/e/a0.json`
- `/Users/soufianeelhabti/kuaishou_audit/secrets_sweep/dex_strings.txt`

The first two contain normal path-property expressions, and DEX strings expose native-Lottie URL APIs plus WebView bridge strings. No same-flow call graph, lottie-web engine, ThorVG renderer, `$bm_mod`, or attacker-controlled delivery was demonstrated.

Provenance limitation: the report-referenced `/Users/soufianeelhabti/Downloads/kwai-13-4-20-544805.apk` is absent, and the audit tree mixes package/version artifacts. The current local split set `/Users/soufianeelhabti/Downloads/com.kwai.video_13.4.20.544805/*.apk` is much smaller and only showed Lottie-Android presence with no delivery proof.

### 3. DBA — bundled Lottie expression plus separate bridged WebViews

- APK: `/Users/soufianeelhabti/DBAndroid/DBA – buy and sell used goods_260225-2baa9f82_apkcombo.com.apk`
- Expression asset: `/Users/soufianeelhabti/dba_analysis/raw/res/i_.json`
- WebView bridge: `/Users/soufianeelhabti/dba_analysis/java/sources/com/example/hybrid/webview/InternalWebView.java:131`

The expression is bundled and ordinary. The app exposes Lottie-Android/dotLottie format markers and several WebView bridges, but no lottie-web or delivery path joins them.

### 4. Cashloan extracted tree mislabeled under AnyTask — local expression asset plus Capacitor/Cordova bridges

- `/Users/soufianeelhabti/Downloads/AnyTask_1.0.6_apkcombo.com/resources/res/raw/onboard_sdk_lottie_tutorial_selfie.json`
- `/Users/soufianeelhabti/Downloads/AnyTask_1.0.6_apkcombo.com/sources/com/getcapacitor/MessageHandler.java:34-38`

The tree identifies `com.didiglobal.cashloan`, so it must not be attributed to the adjacent AnyTask APK split set. It contains a bundled rotation expression and generic bridges, but no lottie-web or same-flow delivery proof.

### 5. Bridge-only families

These contained WebView JavaScript bridges but no lottie-web/bodymovin engine or joined animation-delivery flow:

- Caltex/Ampol: `/Users/soufianeelhabti/ampol/sources/com/reactnativecommunity/webview/RNCWebView.java:236`
- Bambu Handy extracted trees under `/Users/soufianeelhabti/bambolab/work/app-analysis`
- Halara: `/Users/soufianeelhabti/research/Halara_2.6.6_apkcombo.com/halara_apktool_smali/smali_classes3/dj/l0.smali:255`
- Owned test lab: `/Users/soufianeelhabti/research/webview-lab/app/src/main/java/ma/poneglyph/webviewlab/flavors/JsBridgeActivity.kt:44` (attacker URL plus bridge by design, but no Lottie engine)

## Additional app/source roots checked

- `/Users/soufianeelhabti/Downloads/Starbucks+Chile_3.7.2_apkcombo.com/decompiled`
- `/Users/soufianeelhabti/Downloads/tastemade-7-3-12/tastemade_extracted`
- `/Users/soufianeelhabti/research/sap_recon/unzip_out`
- `/Users/soufianeelhabti/research/Halara_2.6.6_apkcombo.com`
- `/Users/soufianeelhabti/rian/app-release.apk` (directory)
- `/Users/soufianeelhabti/Downloads/app-release.apk` (directory)
- `/Users/soufianeelhabti/lottie/rlottieprobe`
- `/Users/soufianeelhabti/lottie/vprobe`
- `/Users/soufianeelhabti/android-privesc-hunt/workspace/com.google.android.verifier.overlay`

No extracted tree supplied the missing lottie-web/bodymovin WebView engine or a proven attacker-controlled animation delivery chain.

## Interpretation rules used

- **Library presence**: a package contains Lottie-Android, rlottie, React-Native dotLottie props, or `.lottie` files.
- **Delivery proof**: an app call path carries externally influenced bytes/URL into that exact renderer.
- **Surface-C proof**: delivery reaches lottie-web/bodymovin in a WebView with a JavaScript interface in the same reachable flow.

No item crossed the delivery and Surface-C proof thresholds. The recorded native/Dex/Hermes marker pass was performed independently. The detector was subsequently extended to identify a stripped or renamed dotLottie native player only when its exported dotLottie C API and multiple ThorVG expression-runtime markers occur in the same ELF; a lone format/property string remains a near miss.
