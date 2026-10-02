package com.example.flow;
class Entry extends Activity {
    void onCreate(Bundle state) {
        Intent next = getIntent().getParcelableExtra("next");
        startActivity(next);
    }
}
