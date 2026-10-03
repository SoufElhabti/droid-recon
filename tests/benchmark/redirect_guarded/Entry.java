package com.example.flow;
class Entry extends Activity {
    void onCreate(Bundle state) {
        Intent next = getIntent().getParcelableExtra("next");
        next.setPackage("com.example.flow");
        startActivity(next);
    }
}
