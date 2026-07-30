/*
 * webview_hooks.js — trace WebView configuration and content loading.
 *
 * Looking for: addJavascriptInterface bridges reachable from loaded content,
 * file:// access enabled alongside universal access (the classic local-file-read
 * chain), and attacker-controllable URLs reaching loadUrl.
 */

Java.perform(function () {
    var WebView = Java.use("android.webkit.WebView");
    var WebSettings = Java.use("android.webkit.WebSettings");

    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("[webview] loadUrl(" + url + ")");
        if (url.indexOf("file://") === 0) {
            console.log("[webview]   <-- file:// URL loaded into a WebView");
        }
        return this.loadUrl(url);
    };

    WebView.loadDataWithBaseURL.implementation = function (base, data, mime, enc, hist) {
        console.log("[webview] loadDataWithBaseURL base=" + base + " mime=" + mime +
                    " dataLen=" + (data ? data.length : 0));
        return this.loadDataWithBaseURL(base, data, mime, enc, hist);
    };

    WebView.addJavascriptInterface.implementation = function (obj, name) {
        var cls = "?";
        try { cls = obj.getClass().getName(); } catch (e) {}
        console.log("[webview] addJavascriptInterface(name=" + name + ", class=" + cls + ")" +
                    "  <-- JS bridge: every @JavascriptInterface method is callable from page JS");
        return this.addJavascriptInterface(obj, name);
    };

    WebView.evaluateJavascript.implementation = function (js, cb) {
        console.log("[webview] evaluateJavascript(" + String(js).substring(0, 200) + ")");
        return this.evaluateJavascript(js, cb);
    };

    // --- dangerous settings ---
    var flags = [
        ["setAllowFileAccessFromFileURLs", "file:// pages can read other file:// URLs"],
        ["setAllowUniversalAccessFromFileURLs", "file:// pages can read ANY origin — full local file read"],
        ["setAllowFileAccess", "file:// scheme permitted"],
        ["setAllowContentAccess", "content:// scheme permitted"],
        ["setJavaScriptEnabled", "JavaScript enabled"],
    ];
    flags.forEach(function (pair) {
        var name = pair[0], why = pair[1];
        try {
            WebSettings[name].implementation = function (enabled) {
                if (enabled) console.log("[webview] " + name + "(true)  <-- " + why);
                return this[name](enabled);
            };
        } catch (e) { /* method absent on this API level */ }
    });

    console.log("[webview] hooks installed");
});
