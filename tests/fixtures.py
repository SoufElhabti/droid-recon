"""Hand-built manifests with deliberately known answers.

These are the correctness gate for the reachability logic — the one piece of the
pipeline where being wrong silently turns the whole tool into a false-positive
generator. Each component below is named for what it should classify as.
"""

from __future__ import annotations

NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'

KNOWN_ANSWERS_MANIFEST = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {NS} package="com.example.target"
    android:versionCode="7" android:versionName="1.2.3">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
  <uses-permission android:name="android.permission.INTERNET"/>

  <permission android:name="com.example.target.permission.WEAK"
              android:protectionLevel="normal"/>
  <permission android:name="com.example.target.permission.STRONG"
              android:protectionLevel="signature"/>

  <application android:allowBackup="true" android:debuggable="true">

    <!-- exported by explicit flag, no guard -> third_party_app -->
    <activity android:name=".ExportedNoGuardActivity" android:exported="true"/>

    <!-- exported + BROWSABLE -> browser -->
    <activity android:name=".BrowsableActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp" android:host="open" android:path="/deep"/>
      </intent-filter>
    </activity>

    <!-- no exported attr BUT has an intent-filter -> exported by inference -->
    <activity android:name=".InferredExportedActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>

    <!-- explicitly not exported -> shell only -->
    <activity android:name=".PrivateActivity" android:exported="false"/>

    <!-- exported but signature-guarded -> none -->
    <activity android:name=".SignatureGuardedActivity" android:exported="true"
              android:permission="com.example.target.permission.STRONG"/>

    <!-- exported guarded by a NORMAL custom permission: any app can hold it
         -> still third_party_app -->
    <activity android:name=".WeaklyGuardedActivity" android:exported="true"
              android:permission="com.example.target.permission.WEAK"/>

    <!-- exported provider, no permission at all -> third_party_app, high risk -->
    <provider android:name=".OpenProvider" android:exported="true"
              android:authorities="com.example.target.open"/>

    <!-- exported provider, read guarded by signature, writes open -> none for read -->
    <provider android:name=".ReadGuardedProvider" android:exported="true"
              android:authorities="com.example.target.guarded"
              android:readPermission="com.example.target.permission.STRONG"/>

    <!-- provider with no exported attr, targetSdk 34 -> NOT exported -->
    <provider android:name=".DefaultProvider"
              android:authorities="com.example.target.default"/>

    <!-- exported provider with grantUriPermissions -> flagged -->
    <provider android:name=".GrantingProvider" android:exported="true"
              android:authorities="com.example.target.grant"
              android:grantUriPermissions="true"/>

    <!-- exported receiver, no guard -->
    <receiver android:name=".OpenReceiver" android:exported="true">
      <intent-filter>
        <action android:name="com.example.target.DO_THING"/>
      </intent-filter>
    </receiver>

    <!-- exported service guarded by a platform signature permission -> none -->
    <service android:name=".JobService" android:exported="true"
             android:permission="android.permission.BIND_JOB_SERVICE"/>

    <!-- SEND target -> Dirty Stream surface -->
    <activity android:name=".ShareActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.SEND"/>
        <data android:mimeType="*/*"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
"""

# name -> (exported, reachable_from)
EXPECTED: dict[str, tuple[bool, str]] = {
    "com.example.target.ExportedNoGuardActivity": (True, "third_party_app"),
    "com.example.target.BrowsableActivity": (True, "browser"),
    "com.example.target.InferredExportedActivity": (True, "third_party_app"),
    "com.example.target.PrivateActivity": (False, "shell"),
    "com.example.target.SignatureGuardedActivity": (True, "none"),
    "com.example.target.WeaklyGuardedActivity": (True, "third_party_app"),
    "com.example.target.OpenProvider": (True, "third_party_app"),
    "com.example.target.ReadGuardedProvider": (True, "none"),
    "com.example.target.DefaultProvider": (False, "shell"),
    "com.example.target.GrantingProvider": (True, "third_party_app"),
    "com.example.target.OpenReceiver": (True, "third_party_app"),
    "com.example.target.JobService": (True, "none"),
    "com.example.target.ShareActivity": (True, "third_party_app"),
}

# A provider whose paths only exist in code, to exercise the UriMatcher extractor.
PROVIDER_JAVA = """
package com.example.target;

import android.content.UriMatcher;

public class OpenProvider extends android.content.ContentProvider {
    static final String AUTHORITY = "com.example.target.open";
    private static final UriMatcher MATCHER = new UriMatcher(UriMatcher.NO_MATCH);

    static {
        MATCHER.addURI(AUTHORITY, "notes", 1);
        MATCHER.addURI(AUTHORITY, "notes/#", 2);
        MATCHER.addURI("com.example.target.open", "secrets", 3);
    }

    public android.database.Cursor query(android.net.Uri uri, String[] p, String s,
                                         String[] a, String o) {
        return getContext().getContentResolver().query(
            android.net.Uri.parse("content://com.example.target.open/notes"), p, s, a, o);
    }
}
"""

SINK_JAVA = """
package com.example.target;

public class BrowsableActivity extends android.app.Activity {
    protected void onCreate(android.os.Bundle b) {
        String url = getIntent().getStringExtra("url");
        android.webkit.WebView wv = new android.webkit.WebView(this);
        wv.getSettings().setAllowUniversalAccessFromFileURLs(true);
        wv.addJavascriptInterface(new Bridge(), "native");
        wv.loadUrl(url);
        startActivity((android.content.Intent) getIntent().getParcelableExtra("next"));
    }
}
"""
