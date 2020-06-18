package com.zimperium.ziap_demo;

/**
 *
 * Copyright © 2018 Zimperium. All rights reserved.
 *
 */

import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
//import android.support.multidex.MultiDex;
//import android.support.v4.content.LocalBroadcastManager;
import android.text.TextUtils;
import android.util.Log;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.multidex.MultiDex;

import com.zimperium.zdetection.api.v1.DetectionState;
import com.zimperium.zdetection.api.v1.DetectionStateCallback;
import com.zimperium.zdetection.api.v1.Threat;
import com.zimperium.zdetection.api.v1.ThreatCallback;
import com.zimperium.zdetection.api.v1.ThreatType;
import com.zimperium.zdetection.api.v1.ZDetection;
//import com.zimperium.ziap_demo.ui.ThreatActivity;

/**
 * The single Application instance for this project.
 * It always listens for the DetectionState changes and the ThreatCallbacks.
 * It would then handle any threats accordingly and lock down sensitive information.
 */
public class ZiapApplication extends Application {

    private DetectionState currentDetectionState = null;
    private static ZiapApplication instance;
    private boolean ziapInitialized = false;
    private boolean ziapDetecting = false;
    private boolean isCompromised = false;

    /**
     * Needed for multidex to not crash on Android 4.4
     */
    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        //if (android.os.Build.VERSION.SDK_INT <= android.os.Build.VERSION_CODES.KITKAT) {
            MultiDex.install(this);
        //}
    }
    
    private void info( final String text ) {
        Log.i("ZiapApplication", text);
    }


    /**
     * Get the single instance of ZiapApplication so it can be called
     * from elsewhere in the project.
     * @return -
     */
    static public ZiapApplication getInstance() {
        return instance;
    }

    public DetectionState getCurrentState() {
        return currentDetectionState;
    }

    private final ThreatCallback criticalThreatCallback = new ThreatCallback() {
        @Override
        public void onThreat(Uri uri, Threat threat) {
            info("CriticalThreats======");
            info("Detected Threat:" +  threat.getHumanThreatName());
            info(" - Severity: " + threat.getSeverity());
            info(" - Type: " + threat.getHumanThreatType());
            info(" - Description: " + threat.getHumanThreatSummary());

            //add to our persistent threat DB

            String extra = ( threat.getThreatType() == ThreatType.APK_SUSPECTED ) ? ((com.zimperium.zdetection.db.model.Threat)threat).getMalwarePath()  : "";

            String description = (threat.getHumanThreatSummary() != null ) ? threat.getHumanThreatSummary().toString() : "";

            info(" - extra: " + extra);

            showThreat(threat);
            broadcastThreat(threat);
       }
    };

    /**
     * Let's the MainActivity know about this threat...
     * @param threat -
     */
    private void broadcastThreat( Threat threat ) {

        //tell anyone else that wants to know
        Intent threatEvent = new Intent("threat-event");
        threatEvent.putExtra("type", threat.getThreatType().ordinal());
        threatEvent.putExtra("severity", threat.getSeverity());
        threatEvent.putExtra("description",  ((threat.getHumanThreatSummary() != null ) ? threat.getHumanThreatSummary().toString() : "") );
        LocalBroadcastManager.getInstance(getApplicationContext()).sendBroadcast(threatEvent);
    }

    /**
     * Launcher
     * @param threat -
     */
    private void showThreat( Threat threat ) {
        //Show the alert.
//        Intent intent = new Intent( getApplicationContext(), ThreatActivity.class );
//        intent.addFlags( Intent.FLAG_ACTIVITY_NEW_TASK );
//        intent.putExtra( "type", threat.getThreatType().ordinal());
//        intent.putExtra( "title", threat.getHumanThreatName() );
//        intent.putExtra( "description", threat.getHumanThreatSummary() != null ? threat.getHumanThreatSummary().toString() : ""  );
//        startActivity( intent );
    }

    private final DetectionStateCallback detectionStateCallback = new DetectionStateCallback() {
        @Override
        public void onStateChanged(DetectionState oldState, DetectionState newState) {
            info("\tonStateChanged: " + newState);
            currentDetectionState = newState;
        }
    };

    public void onCreate(){
        super.onCreate();
        instance = this;
    }

    /**
     * Set license from resource.
     * add DetectionState callback.
     * Initialize the detection instance with our configuration -- it kicks off the
     * authentication process.
     */
    public void initializeZiap() {
        info("initializeZiap()");
        if( !ziapInitialized ) {
            ziapInitialized = true;

            try {
                ZDetection.setLicenseKey(getApplicationContext(), ZiapKey.LICENSE.getBytes());
                ZDetection.setDeviceId( getDeviceName());
                ZDetection.setTrackingIds("LOGIN", "EMMMMMA");
                ZDetection.addDetectionStateCallback(detectionStateCallback);

            } catch (Exception e ) {
                ziapInitialized = false;
                //
                info("\tException: " + e );
            }
        }
    }

    /**
     * Stop all the threat callbacks.
     */
    public void stopZiap() {
        info("stopZiap()");
        if( ziapDetecting ) {
            ziapDetecting = false;
            ZDetection.stopDetecting(criticalThreatCallback);
        }
    }
    public static String getDeviceName() {
        String manufacturer = Build.MANUFACTURER;
        String model = Build.MODEL;
        if (model.startsWith(manufacturer)) {
            return capitalize(model);
        }
        return capitalize(manufacturer) + " " + model;
    }

    private static String capitalize(String str) {
        if (TextUtils.isEmpty(str)) {
            return str;
        }
        char[] arr = str.toCharArray();
        boolean capitalizeNext = true;

        StringBuilder phrase = new StringBuilder();
        for (char c : arr) {
            if (capitalizeNext && Character.isLetter(c)) {
                phrase.append(Character.toUpperCase(c));
                capitalizeNext = false;
                continue;
            } else if (Character.isWhitespace(c)) {
                capitalizeNext = true;
            }
            phrase.append(c);
        }

        return phrase.toString();
    }
    public void startDetection() {
        if( !ziapDetecting ) {
            ziapDetecting = true;
            ZDetection.detectAllThreats(getApplicationContext(), criticalThreatCallback);
        }
    }

}
