package com.zimperium.ziap_demo.ui;

/**
 *
 * Copyright © 2018 Zimperium. All rights reserved.
 *
 */

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import com.zimperium.ziap_demo.R;


/**
 *
 *
 */
public class ThreatActivity extends Activity {
    private void info( final String text ) {
        Log.e("ThreatActivity", text);

    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_threat);

        TextView title = findViewById(R.id.title);
        title.setText(  getIntent().getStringExtra( "title" ) );

        TextView message = findViewById(R.id.message);
        message.setText(  getIntent().getStringExtra( "description" ) );

        info("Title: " +  getIntent().getStringExtra( "title" ));
        info("Description: " +  getIntent().getStringExtra( "description" ));


        findViewById(R.id.ok_action).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                finish();
            }
        });

    }

}
