package com.example.flow;
class Entry extends Activity {
    void onCreate(Bundle state) {
        String user = getIntent().getStringExtra("user");
        db.rawQuery("SELECT * FROM users WHERE name=?", new String[]{user});
    }
}
