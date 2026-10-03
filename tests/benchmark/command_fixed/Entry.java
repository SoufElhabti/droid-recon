package com.example.flow;
class Entry extends Activity {
    void onCreate(Bundle state) throws Exception {
        String action = getIntent().getStringExtra("action");
        if ("sync".equals(action)) {
            Runtime.getRuntime().exec("/system/bin/sync");
        }
    }
}
