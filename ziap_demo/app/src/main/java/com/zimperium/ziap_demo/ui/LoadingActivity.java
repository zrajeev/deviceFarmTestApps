package com.zimperium.ziap_demo.ui;

/**
 *
 * Copyright © 2018 Zimperium. All rights reserved.
 *
 */

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.ImageView;
import android.widget.TextView;


import com.zimperium.zdetection.api.v1.ZDetection;
import com.zimperium.zdetection.api.v1.ZThreatDisposition;
import com.zimperium.zdetection.api.v1.enums.ZEngineState;
import com.zimperium.zdetection.internal.ZDetectionInternal;
import com.zimperium.ziap_demo.R;
import com.zimperium.ziap_demo.ZiapApplication;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * This is the example activity for loading ziap before entering your main application.
 *
 * 1) Initialize ziap -- Authenticate with the server
 * 2) Quick scan all the apps (HTTP)
 * 3) Start native detection
 * 4) Load the MainActivity when all clear.
 *
 * When the application is launched it, if the ziap is still logged in and detecting, it just launches
 * into the MainActivity.
 */
public class LoadingActivity extends Activity  {

    private static void info(String text) {
        Log.i("LoadingActivity", text);
    }


    private void cancelProgress() {
        animateIcon(false);
    }

    /**
     * Launches into the example MainActivity
     */
    private void onFullyLoaded() {
        info("onFullyLoaded()");
        cancelProgress();

        //Fully loaded, start detection.
        ZiapApplication.getInstance().startDetection();

        Intent intent = new Intent(LoadingActivity.this, MainActivity.class);
        startActivity(intent);
        finish();
    }

    @Override
    public void onResume() {
        super.onResume();
        info("onResume()");
        animateIcon(true);
        new ResumeThread().start();
    }

    public String formatDate(long epoch) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault());
        return dateFormat.format( new Date(epoch) );
    }

    private class ResumeThread extends Thread {

        public void run() {

            clearText();
            setText( "Loading zIAP");
            setText( "Creating ZThreatDisposition" );
            ZThreatDisposition disposition = new ZThreatDisposition(getApplicationContext());
            setText("Checking Malware Threats.");

            if (disposition.hasMalwareThreat()) {
                cancelProgress();

                StringBuilder message = new StringBuilder();

                for( String threatPackage : disposition.getInstalledMalware() ){
                    message.append("\nInstalled: ");
                    message.append(threatPackage);
                }

                for( File threatFile : disposition.getDownloadedMalware() ){
                    message.append("\nDownloaded: ");
                    message.append(threatFile.getPath());
                }

                setText(message.toString());
            }

            setText("Checking Compromised.");
            if (disposition.isCompromised()) {
                cancelProgress();
                setText("Device is compromised.");
            }

            setText("Checking root.");
            if (disposition.isRooted()) {
                cancelProgress();
                setText("Device is rooted.");
            }

            if(ZDetectionInternal.getDetectionState().engineState!= ZEngineState.DETECTING) {
                setText("Not Detecting yet - Running quick scan..");
                String[] malwareFound = ZDetection.runQuickMalwareScan(getApplicationContext());
                if (malwareFound != null && malwareFound.length > 0) {
                    cancelProgress();
                    setText("Quick scan found: " + malwareFound[0]);
                }
            }

            setText("Fully loaded - click to continue" );
            TextView textView = findViewById(R.id.loading_text);
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    textView.setOnClickListener(new View.OnClickListener() {
                        @Override
                        public void onClick(View view) {
                            onFullyLoaded();
                        }
                    });
                }
            });

            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Thread.sleep(20000L);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            onFullyLoaded();
                        }
                    });
                }
            }).start();;


        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_loading);
        info("onCreate()");
    }

    @Override
    protected void onStart() {
        super.onStart();
        //If we are fully loaded, just transition into the MainActivity
        ZiapApplication.getInstance().initializeZiap();
    }


    /**
     * Throb the logo to indicate action to the user.
     * @param enable -
     */
    private void animateIcon(final boolean enable) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                ImageView myImageView= findViewById(R.id.loading_image);
                if( enable ) {
                    Animation myFadeInAnimation = AnimationUtils.loadAnimation(LoadingActivity.this, R.anim.loading_animation);
                    myImageView.startAnimation(myFadeInAnimation);
                } else {
                    myImageView.clearAnimation();
                    //Show the icon in distress since we aren't fully loaded.
                }
            }
        });
    }

    /**
     * Helper method to populate the state TextViews.
     * Runs in the main thread.
     * @param text -
     */
    private void setText( final String text ) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                TextView textView = findViewById(R.id.loading_text);
                if( textView != null ) {
                    textView.setText( textView.getText() + "\n" + formatDate(System.currentTimeMillis()) +": " + text );
                }
            }
        });
    }
    private void clearText(  ) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                TextView textView = findViewById(R.id.loading_text);
                if( textView != null ) {
                    textView.setText("");
                }
            }
        });
    }

}
