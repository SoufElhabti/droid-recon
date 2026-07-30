/*
 * crypto_logger.js — log javax.crypto usage: algorithms, modes, keys, IVs.
 *
 * Looking for: hardcoded keys, ECB mode, static IVs, and keys derived from
 * predictable material. Prints one [crypto] line per event so the output can be
 * grepped straight out of the session log.
 */

Java.perform(function () {
    function hex(bytes) {
        if (!bytes) return "null";
        var out = [];
        for (var i = 0; i < bytes.length && i < 64; i++) {
            out.push(("0" + (bytes[i] & 0xff).toString(16)).slice(-2));
        }
        return out.join("") + (bytes.length > 64 ? "..." : "") + " (" + bytes.length + "B)";
    }

    function printable(bytes) {
        if (!bytes) return "";
        try {
            var s = Java.use("java.lang.String").$new(bytes);
            return /^[\x20-\x7e]{4,}$/.test(s) ? " ascii=" + s.substring(0, 80) : "";
        } catch (e) { return ""; }
    }

    // --- Cipher.getInstance: flags weak modes at the point of choice ---
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function (t) {
        var warn = /ECB/i.test(t) ? "  <-- ECB: identical plaintext blocks leak" : "";
        console.log("[crypto] Cipher.getInstance(" + t + ")" + warn);
        return this.getInstance(t);
    };

    // --- SecretKeySpec: this is where hardcoded keys surface ---
    var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
    SKS.$init.overload("[B", "java.lang.String").implementation = function (key, alg) {
        console.log("[crypto] SecretKeySpec alg=" + alg + " key=" + hex(key) + printable(key));
        return this.$init(key, alg);
    };

    // --- IvParameterSpec: static/zero IVs ---
    var IVS = Java.use("javax.crypto.spec.IvParameterSpec");
    IVS.$init.overload("[B").implementation = function (iv) {
        var allZero = true;
        for (var i = 0; i < iv.length; i++) { if (iv[i] !== 0) { allZero = false; break; } }
        console.log("[crypto] IvParameterSpec iv=" + hex(iv) + (allZero ? "  <-- ALL ZERO IV" : ""));
        return this.$init(iv);
    };

    // --- MessageDigest: MD5/SHA1 usage ---
    var MD = Java.use("java.security.MessageDigest");
    MD.getInstance.overload("java.lang.String").implementation = function (alg) {
        var warn = /^(MD5|SHA-?1)$/i.test(alg) ? "  <-- broken hash" : "";
        console.log("[crypto] MessageDigest.getInstance(" + alg + ")" + warn);
        return this.getInstance(alg);
    };

    // --- PBE key derivation: iteration counts that are too low ---
    try {
        var PBE = Java.use("javax.crypto.spec.PBEKeySpec");
        PBE.$init.overload("[C", "[B", "int", "int").implementation = function (pw, salt, iter, len) {
            var warn = iter < 10000 ? "  <-- low iteration count" : "";
            console.log("[crypto] PBEKeySpec iterations=" + iter + " keylen=" + len +
                        " salt=" + hex(salt) + warn);
            return this.$init(pw, salt, iter, len);
        };
    } catch (e) { /* not present */ }

    console.log("[crypto] hooks installed");
});
