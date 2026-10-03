package com.example.flow;
class Entry extends Activity {
    void onCreate(Bundle state) {
        String url = getIntent().getStringExtra("url");
        webView.loadUrl(url);
    }
}
