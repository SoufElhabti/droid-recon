package com.example.flow;
class Entry extends Activity {
    void onCreate(Bundle state) {
        String url = getIntent().getStringExtra("url");
        Uri parsed = Uri.parse(url);
        if (!"https".equals(parsed.getScheme()) ||
                !"safe.example".equals(parsed.getHost())) {
            return;
        }
        webView.loadUrl(url);
    }
}
