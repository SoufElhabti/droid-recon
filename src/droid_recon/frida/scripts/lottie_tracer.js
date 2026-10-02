/*
 * lottie_tracer.js -- trace where Android Lottie compositions come from.
 *
 * This is an observation-only script. It hooks public composition-factory entry
 * points, emits bounded/sanitized argument previews, and records the Java stack at
 * the call site. It never reads an InputStream/ZipInputStream or changes a result.
 *
 * Coverage:
 *   - lottie-android 3.x through 6.x public LottieCompositionFactory APIs;
 *   - LottieFiles dotLottie Android's public JNI data/string load APIs;
 *   - Telegram/Samsung rlottie wrappers, including renamed native libraries;
 *   - newer aliases such as fromInputStream/fromJsonSource;
 *   - relocated classes whose LottieCompositionFactory simple name survives;
 *   - R8-renamed factories when their distinctive public signature family survives.
 *
 * Output is line-oriented so droid-recon can return it unchanged:
 *   [lottie] HOOKED {...}
 *   [lottie] EVENT {... "args":[...], "stack":[...]}
 *
 * A heuristic match is labelled as such. Treat it as a lead and confirm that its
 * event previews/stacks are Lottie-related before making any claim about an app.
 */

"use strict";

(function () {
    var PREFIX = "[lottie] ";
    var CANONICAL_FACTORY = "com.airbnb.lottie.LottieCompositionFactory";
    var DOTLOTTIE_PLAYER = "com.lottiefiles.dotlottie.core.jni.DotLottiePlayer";
    var MAX_EVENTS = 80;
    var MAX_STACK_FRAMES = 24;
    var MAX_PREVIEW = 180;
    var SCAN_INTERVAL_MS = 2500;
    var MAX_SCAN_PASSES = 6;

    // Prefix matching intentionally includes Sync overloads. Private *Internal
    // implementations are filtered explicitly when method metadata is indexed.
    var ENTRY_PREFIXES = [
        "fromJsonString",
        "fromJsonInputStream",
        "fromJsonReader",
        "fromJsonSource",       // added in recent 6.x releases
        "fromInputStream",      // format-detecting alias in recent 6.x releases
        "fromJson",             // JSONObject entry point in older/current releases
        "fromUrl",
        "fromAsset",
        "fromRawRes",
        "fromZipStream"
    ];
    var RLOTTIE_ENTRY_NAMES = [
        "createWithJson", "create", "setAnimation", "asLottie"
    ];
    var DOTLOTTIE_LOAD_NAMES = [
        "nativeLoadAnimationData",
        "nativeLoadAnimationPath",
        "nativeLoadAnimation",
        "nativeLoadDotLottieData"
    ];

    var hookedOverloads = Object.create(null);
    var indexedClasses = Object.create(null);
    var activeByThread = Object.create(null);
    var scanRunning = false;
    var factoryFound = false;
    var dotlottieFound = false;
    var rlottieFound = false;
    var scanPasses = 0;
    var eventCount = 0;

    function log(kind, value) {
        if (typeof value === "string") {
            console.log(PREFIX + kind + " " + value);
        } else {
            console.log(PREFIX + kind + " " + JSON.stringify(value));
        }
    }

    if (typeof Java === "undefined" || !Java.available) {
        log("ERROR", "Java runtime is unavailable");
        return;
    }

    Java.perform(function () {
        var Thread = Java.use("java.lang.Thread");

        function startsWithAny(value, prefixes) {
            for (var i = 0; i < prefixes.length; i++) {
                if (value.indexOf(prefixes[i]) === 0) return true;
            }
            return false;
        }

        function isKnownEntryName(name) {
            return startsWithAny(name, ENTRY_PREFIXES);
        }

        function javaClassName(value) {
            if (value === null || value === undefined) return "null";
            try {
                return String(value.getClass().getName());
            } catch (e) {
                return typeof value;
            }
        }

        function escapeControls(value) {
            return value
                .replace(/[\r\n\t]/g, function (ch) {
                    return ch === "\r" ? "\\r" : (ch === "\n" ? "\\n" : "\\t");
                })
                .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "?");
        }

        function redactSecrets(value) {
            var out = value;
            // Authorization headers and common key/value forms.
            out = out.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+\/-]+=*/gi,
                              "$1 <redacted>");
            out = out.replace(/((?:access[_-]?token|refresh[_-]?token|auth(?:orization)?|password|passwd|secret|session|cookie|api[_-]?key)\s*[=:]\s*)[^\s,&;}]+/gi,
                              "$1<redacted>");
            // Quoted JSON values for sensitive-looking keys.
            out = out.replace(/("(?:access[_-]?token|refresh[_-]?token|auth(?:orization)?|password|passwd|secret|session|cookie|api[_-]?key)"\s*:\s*")[^"]*(")/gi,
                              "$1<redacted>$2");
            return out;
        }

        function sanitizeUrl(value) {
            if (/^data:/i.test(value)) {
                return "data:<redacted> (chars=" + value.length + ")";
            }
            var out = value;
            // Strip URL userinfo but retain scheme/host/path: the latter is the useful
            // delivery-path evidence.
            out = out.replace(/(^[A-Za-z][A-Za-z0-9+.-]*:\/\/)[^\/@?#]+@/, "$1<redacted>@");
            // Query names are useful; values and fragments commonly carry credentials.
            out = out.replace(/([?&][^=&#\s]+)=([^&#\s]*)/g, "$1=<redacted>");
            out = out.replace(/#.*$/, "#<redacted>");
            return redactSecrets(out);
        }

        function clipped(value) {
            var text = escapeControls(redactSecrets(String(value)));
            if (text.length > MAX_PREVIEW) {
                return text.substring(0, MAX_PREVIEW) + "... (chars=" + text.length + ")";
            }
            return text;
        }

        function previewString(value) {
            var raw = String(value);
            if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(raw) || /^data:/i.test(raw)) {
                return "url=" + clipped(sanitizeUrl(raw));
            }
            var trimmed = raw.replace(/^\s+/, "");
            if (trimmed.charAt(0) === "{" || trimmed.charAt(0) === "[") {
                return "json(chars=" + raw.length + ")=" + clipped(raw);
            }
            return "string(chars=" + raw.length + ")=" + clipped(raw);
        }

        function isType(typeName, suffix) {
            return typeName === suffix ||
                   (typeName.length >= suffix.length &&
                    typeName.indexOf(suffix, typeName.length - suffix.length) !== -1);
        }

        function previewArgument(value, declaredType) {
            if (value === null || value === undefined) return "null";
            try {
                if (declaredType === "java.lang.String") return previewString(value);
                if (declaredType === "int" || declaredType === "long" ||
                    declaredType === "short" || declaredType === "byte") {
                    var n = Number(value);
                    if (declaredType === "int" && n >= 0) {
                        return "number=" + n + " (0x" + n.toString(16) + ")";
                    }
                    return "number=" + n;
                }
                if (declaredType === "boolean") return "boolean=" + String(value);
                if (declaredType === "[B") return "byte-array(len=" + value.length + ")";

                if (declaredType === "android.content.Context" ||
                    isType(declaredType, ".Context")) {
                    var pkg = "?";
                    try { pkg = String(value.getPackageName()); } catch (ignored) {}
                    return "Context(package=" + clipped(pkg) + ")";
                }

                if (declaredType === "java.net.URL" || declaredType === "android.net.Uri") {
                    return "url=" + clipped(sanitizeUrl(String(value.toString())));
                }
                if (declaredType === "java.io.File") {
                    return "File(path=" + clipped(String(value.getPath())) + ")";
                }
                if (declaredType === "org.json.JSONObject") {
                    var jsonLength = "?";
                    try { jsonLength = String(value.length()); } catch (ignored2) {}
                    return "JSONObject(keys=" + jsonLength + ")";
                }

                // Do not call read(), mark(), reset(), getNextEntry(), or toString() on
                // streams/readers. Even a preview must not perturb the target.
                var actual = javaClassName(value);
                if (declaredType.indexOf("InputStream") !== -1 ||
                    actual.indexOf("InputStream") !== -1 ||
                    declaredType.indexOf("JsonReader") !== -1 ||
                    declaredType.indexOf("Source") !== -1 ||
                    declaredType.indexOf("Reader") !== -1) {
                    return "opaque(class=" + clipped(actual) + ")";
                }
                return "object(class=" + clipped(actual) + ")";
            } catch (e) {
                return "preview-error(class=" + clipped(javaClassName(value)) + ")";
            }
        }

        function stackTrace() {
            var frames = [];
            try {
                var raw = Thread.currentThread().getStackTrace();
                for (var i = 0; i < raw.length && frames.length < MAX_STACK_FRAMES; i++) {
                    var frame = String(raw[i].toString());
                    if (frame.indexOf("java.lang.Thread.getStackTrace") === 0) continue;
                    frames.push(clipped(frame));
                }
            } catch (e) {
                frames.push("<stack unavailable: " + clipped(String(e)) + ">");
            }
            return frames;
        }

        function overloadTypes(overload) {
            var types = [];
            for (var i = 0; i < overload.argumentTypes.length; i++) {
                var t = overload.argumentTypes[i];
                types.push(String(t.className || t.name || t));
            }
            return types;
        }

        function methodKey(className, methodName, types) {
            return className + "." + methodName + "(" + types.join(",") + ")";
        }

        function inferEntry(methodName, types, args) {
            if (isKnownEntryName(methodName)) return methodName;
            if (DOTLOTTIE_LOAD_NAMES.indexOf(methodName) !== -1) {
                return "dotlottie-" + methodName;
            }
            if (RLOTTIE_ENTRY_NAMES.indexOf(methodName) !== -1) {
                return "rlottie-" + methodName;
            }
            var joined = "," + types.join(",") + ",";
            if (joined.indexOf(",java.util.zip.ZipInputStream,") !== -1) return "fromZipStream-like";
            if (joined.indexOf(",java.io.InputStream,") !== -1) return "fromInputStream-like";
            if (joined.indexOf(",org.json.JSONObject,") !== -1) return "fromJson-like";
            if (joined.indexOf(",android.content.Context,int,") !== -1) return "fromRawRes-like";
            if (joined.indexOf(",android.content.Context,java.lang.String,") !== -1) {
                for (var i = 0; i < types.length; i++) {
                    if (types[i] === "java.lang.String" && args[i] !== null) {
                        var s = String(args[i]);
                        return /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(s) ?
                            "fromUrl-like" : "fromAsset-orUrl-like";
                    }
                }
            }
            if (types.length && types[0] === "java.lang.String") return "fromJsonString-like";
            return "composition-factory-entry";
        }

        function emitEvent(className, methodName, mode, overload, args) {
            if (eventCount >= MAX_EVENTS) {
                if (eventCount === MAX_EVENTS) {
                    log("LIMIT", "event limit reached (" + MAX_EVENTS + "); hooks remain active");
                }
                eventCount++;
                return;
            }
            eventCount++;
            var types = overloadTypes(overload);
            var previews = [];
            for (var i = 0; i < args.length; i++) {
                previews.push("arg" + i + ":" + types[i] + "=" +
                              previewArgument(args[i], types[i]));
            }
            log("EVENT", {
                id: eventCount,
                factory: className,
                method: methodName,
                entry: inferEntry(methodName, types, args),
                mode: mode,
                args: previews,
                stack: stackTrace()
            });
        }

        function hookOverload(wrapper, className, methodName, overload, mode) {
            var types = overloadTypes(overload);
            var key = methodKey(className, methodName, types);
            if (hookedOverloads[key]) return false;
            hookedOverloads[key] = true;

            overload.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                var tid = "?";
                try { tid = String(Thread.currentThread().getId()); } catch (ignored) {}
                var depth = activeByThread[tid] || 0;
                activeByThread[tid] = depth + 1;
                try {
                    // Suppress only synchronous factory-to-factory delegation. A later
                    // async worker call is a new top-level event and remains visible.
                    if (depth === 0) emitEvent(className, methodName, mode, overload, args);
                    return overload.apply(this, args);
                } finally {
                    if (depth === 0) delete activeByThread[tid];
                    else activeByThread[tid] = depth;
                }
            };
            return true;
        }

        function parseMethodDescriptor(descriptor) {
            // Java.enumerateMethods(.../s) returns e.g.
            //   fromUrl(android.content.Context, java.lang.String): com.foo.Task
            var text = String(descriptor);
            var open = text.indexOf("(");
            var close = text.lastIndexOf("):");
            if (open <= 0 || close < open) return null;
            var argsText = text.substring(open + 1, close).trim();
            return {
                name: text.substring(0, open),
                types: argsText ? argsText.split(", ") : [],
                returns: text.substring(close + 2).trim()
            };
        }

        function strongShape(types) {
            var joined = "," + types.join(",") + ",";
            if (joined.indexOf(",java.util.zip.ZipInputStream,") !== -1) return "zip";
            if (joined.indexOf(",java.io.InputStream,") !== -1) return "input";
            if (joined.indexOf(",org.json.JSONObject,") !== -1) return "json-object";
            if (joined.indexOf(",android.content.Context,int,") !== -1) return "raw-res";
            if (joined.indexOf(",android.content.Context,java.lang.String,") !== -1) return "context-string";
            if (types.length >= 2 && types[0] === "java.lang.String" &&
                types[1] === "java.lang.String") return "string-string";
            return null;
        }

        function hasEntryLikeParameter(types) {
            for (var i = 0; i < types.length; i++) {
                var typeName = types[i];
                if (typeName === "java.lang.String" || typeName === "int" ||
                    typeName === "android.content.Context" ||
                    typeName === "java.io.InputStream" ||
                    typeName === "java.util.zip.ZipInputStream" ||
                    typeName === "org.json.JSONObject" ||
                    typeName.indexOf("JsonReader") !== -1 ||
                    typeName.indexOf("Source") !== -1) return true;
            }
            return false;
        }

        function classifyFactory(className, methods) {
            var lower = className.toLowerCase();
            var simpleNameMatch = /(^|\.)lottiecompositionfactory$/.test(lower);
            var knownNames = 0;
            var shapes = Object.create(null);
            var shapedMethods = 0;
            var returnVotes = Object.create(null);

            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                if (isKnownEntryName(method.name)) knownNames++;
                var shape = strongShape(method.types);
                if (shape && method.returns !== "void") {
                    shapes[shape] = true;
                    shapedMethods++;
                    returnVotes[method.returns] = (returnVotes[method.returns] || 0) + 1;
                }
            }

            if (className === CANONICAL_FACTORY) {
                return {mode: "canonical", returns: null};
            }
            if (simpleNameMatch && knownNames > 0) {
                return {mode: "relocated", returns: null};
            }
            if (knownNames >= 4 && shapedMethods >= 3) {
                return {mode: "named-signature", returns: null};
            }

            var shapeCount = Object.keys(shapes).length;
            var rankedReturns = Object.keys(returnVotes).sort(function (a, b) {
                return returnVotes[b] - returnVotes[a];
            });
            var bestVotes = rankedReturns.length ? returnVotes[rankedReturns[0]] : 0;
            // A full/mostly-full Lottie factory has the otherwise unusual combination
            // Context+String, Context+int, InputStream and ZipInputStream overloads, all
            // returning one of two task/result types. Requiring several independent
            // shapes keeps this fallback conservative.
            if (shapeCount >= 3 && shapedMethods >= 5 && bestVotes >= 3) {
                var returns = Object.create(null);
                for (var r = 0; r < rankedReturns.length && r < 2; r++) {
                    if (returnVotes[rankedReturns[r]] >= 2) returns[rankedReturns[r]] = true;
                }
                return {mode: "obfuscated-signature", returns: returns};
            }
            return null;
        }

        function wrapperFor(className, loader) {
            if (loader !== null && loader !== undefined) {
                try { return Java.ClassFactory.get(loader).use(className); } catch (ignored) {}
            }
            return Java.use(className);
        }

        function installFactory(className, methods, loader) {
            var classification = classifyFactory(className, methods);
            if (!classification) return false;

            var wrapper = wrapperFor(className, loader);
            var allowed = Object.create(null);
            var methodNames = Object.create(null);
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var keep;
                if (classification.mode === "obfuscated-signature") {
                    keep = !!classification.returns[method.returns] &&
                           hasEntryLikeParameter(method.types) && method.types.length <= 4;
                } else {
                    keep = isKnownEntryName(method.name) &&
                           method.name.indexOf("Internal") === -1;
                }
                if (!keep) continue;
                allowed[methodKey(className, method.name, method.types)] = true;
                methodNames[method.name] = true;
            }

            var installed = 0;
            var names = Object.keys(methodNames);
            for (var n = 0; n < names.length; n++) {
                var methodName = names[n];
                var dispatcher;
                try { dispatcher = wrapper[methodName]; } catch (ignored2) { continue; }
                if (!dispatcher || !dispatcher.overloads) continue;
                for (var o = 0; o < dispatcher.overloads.length; o++) {
                    var overload = dispatcher.overloads[o];
                    // Frida's Java bridge uses type=2 for static methods. Keep the
                    // fallback compatible with bridges that do not expose this detail.
                    if (overload.type !== undefined && overload.type !== 2) continue;
                    var key = methodKey(className, methodName, overloadTypes(overload));
                    if (!allowed[key]) continue;
                    if (hookOverload(wrapper, className, methodName, overload,
                                     classification.mode)) installed++;
                }
            }

            if (installed > 0) {
                factoryFound = true;
                log("HOOKED", {
                    factory: className,
                    mode: classification.mode,
                    overloads: installed,
                    methods: names.sort()
                });
                if (classification.mode === "obfuscated-signature") {
                    log("NOTICE", "signature-based match; confirm Lottie in EVENT stacks/previews");
                }
                return true;
            }
            return false;
        }

        function classifyRlottie(className, methods) {
            var lower = className.toLowerCase();
            var names = Object.create(null);
            for (var i = 0; i < methods.length; i++) names[methods[i].name] = true;

            if (lower.indexOf("rlottie") !== -1 &&
                names.createWithJson && names.getFrame) {
                return {mode: "rlottie-native-wrapper", names: {
                    createWithJson: true, create: true
                }};
            }
            if (lower.indexOf("rlottie") !== -1 && names.setAnimation &&
                lower.indexOf("imageview") !== -1) {
                return {mode: "rlottie-view", names: {setAnimation: true}};
            }
            if (lower.indexOf("sticker") !== -1 && names.asLottie) {
                return {mode: "rlottie-sticker-delivery", names: {asLottie: true}};
            }
            return null;
        }

        function installRlottie(className, methods, loader) {
            var classification = classifyRlottie(className, methods);
            if (!classification) return false;

            var wrapper = wrapperFor(className, loader);
            var installed = 0;
            var names = Object.keys(classification.names);
            for (var n = 0; n < names.length; n++) {
                var methodName = names[n];
                var dispatcher;
                try { dispatcher = wrapper[methodName]; } catch (ignored) { continue; }
                if (!dispatcher || !dispatcher.overloads) continue;
                for (var o = 0; o < dispatcher.overloads.length; o++) {
                    if (hookOverload(wrapper, className, methodName,
                                     dispatcher.overloads[o], classification.mode)) {
                        installed++;
                    }
                }
            }
            if (!installed) return false;

            rlottieFound = true;
            log("HOOKED", {
                factory: className,
                mode: classification.mode,
                overloads: installed,
                methods: names.sort()
            });
            return true;
        }

        function installCanonicalDirect() {
            var wrapper;
            try {
                wrapper = Java.use(CANONICAL_FACTORY);
            } catch (e) {
                log("WAITING", "canonical factory not resolved; indexing relocated/obfuscated signatures");
                return false;
            }

            // Install the known public names before the full application method index.
            // On a large attached app enumerateMethods() can take several seconds; doing
            // this first prevents an interaction during that window from disappearing.
            var candidateNames = Object.create(null);
            for (var p = 0; p < ENTRY_PREFIXES.length; p++) {
                candidateNames[ENTRY_PREFIXES[p]] = true;
                candidateNames[ENTRY_PREFIXES[p] + "Sync"] = true;
            }
            var installed = 0;
            var hookedNames = [];
            var names = Object.keys(candidateNames);
            for (var n = 0; n < names.length; n++) {
                var methodName = names[n];
                var dispatcher;
                try { dispatcher = wrapper[methodName]; } catch (ignored) { continue; }
                if (!dispatcher || !dispatcher.overloads) continue;
                var methodInstalled = 0;
                for (var o = 0; o < dispatcher.overloads.length; o++) {
                    if (hookOverload(wrapper, CANONICAL_FACTORY, methodName,
                                     dispatcher.overloads[o], "canonical")) {
                        installed++;
                        methodInstalled++;
                    }
                }
                if (methodInstalled) hookedNames.push(methodName);
            }
            if (installed) {
                factoryFound = true;
                log("HOOKED", {
                    factory: CANONICAL_FACTORY,
                    mode: "canonical-direct",
                    overloads: installed,
                    methods: hookedNames.sort()
                });
            }
            return installed > 0;
        }

        function installDotLottieDirect() {
            var wrapper;
            try {
                wrapper = Java.use(DOTLOTTIE_PLAYER);
            } catch (e) {
                log("WAITING", "canonical dotLottie JNI player not resolved");
                return false;
            }

            var installed = 0;
            var hookedNames = [];
            for (var n = 0; n < DOTLOTTIE_LOAD_NAMES.length; n++) {
                var methodName = DOTLOTTIE_LOAD_NAMES[n];
                var dispatcher;
                try { dispatcher = wrapper[methodName]; } catch (ignored) { continue; }
                if (!dispatcher || !dispatcher.overloads) continue;
                var methodInstalled = 0;
                for (var o = 0; o < dispatcher.overloads.length; o++) {
                    if (hookOverload(wrapper, DOTLOTTIE_PLAYER, methodName,
                                     dispatcher.overloads[o],
                                     "dotlottie-native-player")) {
                        installed++;
                        methodInstalled++;
                    }
                }
                if (methodInstalled) hookedNames.push(methodName);
            }
            if (installed) {
                dotlottieFound = true;
                log("HOOKED", {
                    factory: DOTLOTTIE_PLAYER,
                    mode: "dotlottie-native-player",
                    overloads: installed,
                    methods: hookedNames.sort()
                });
            }
            return installed > 0;
        }

        function indexFactories() {
            if (scanRunning) return;
            scanRunning = true;
            scanPasses++;
            try {
                // /s includes signatures; /u restricts the index to application-defined
                // classes. This uses Frida's ART class model and deliberately avoids Java
                // reflection over arbitrary classes (which can force unresolved types).
                var groups = Java.enumerateMethods("*!*/su");
                for (var g = 0; g < groups.length; g++) {
                    var group = groups[g];
                    for (var c = 0; c < group.classes.length; c++) {
                        var entry = group.classes[c];
                        var className = String(entry.name);
                        if (indexedClasses[className]) continue;
                        var methods = [];
                        for (var m = 0; m < entry.methods.length; m++) {
                            var parsed = parseMethodDescriptor(entry.methods[m]);
                            if (parsed) methods.push(parsed);
                        }
                        indexedClasses[className] = true;
                        try { installFactory(className, methods, group.loader); } catch (ignored) {}
                        try { installRlottie(className, methods, group.loader); } catch (ignored2) {}
                    }
                }
            } catch (e) {
                log("NOTICE", "method index failed: " + clipped(String(e)));
            } finally {
                scanRunning = false;
            }
        }

        function scheduleIndex() {
            if (scanPasses >= MAX_SCAN_PASSES) return;
            setTimeout(function () {
                Java.perform(function () {
                    indexFactories();
                    scheduleIndex();
                });
            }, SCAN_INTERVAL_MS);
        }

        installCanonicalDirect();
        installDotLottieDirect();
        indexFactories();
        scheduleIndex();
        log("READY", {
            canonical: CANONICAL_FACTORY,
            dotlottiePlayer: DOTLOTTIE_PLAYER,
            entryPrefixes: ENTRY_PREFIXES,
            dotlottieEntries: DOTLOTTIE_LOAD_NAMES,
            rlottieEntries: RLOTTIE_ENTRY_NAMES,
            streamPolicy: "opaque-preview-only",
            discovery: "Frida method index (/su), no arbitrary-class reflection",
            attachHint: "for obfuscated apps, repeat the interaction after HOOKED appears",
            scanPasses: MAX_SCAN_PASSES,
            eventLimit: MAX_EVENTS
        });
    });
})();
