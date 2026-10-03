package com.example.flow;
class Entry extends Activity {
    void onCreate(Bundle state) throws Exception {
        String command = getIntent().getStringExtra("command");
        Runtime.getRuntime().exec(command);
    }
}
