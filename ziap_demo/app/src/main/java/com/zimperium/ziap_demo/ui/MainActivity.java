package com.zimperium.ziap_demo.ui;

/**
 * Copyright © 2018 Zimperium. All rights reserved.
 */

import android.Manifest;
import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.zimperium.zdetection.api.v1.Threat;
import com.zimperium.zdetection.api.v1.ZDetection;
import com.zimperium.zdetection.api.v1.ZDetectionTester;
import com.zimperium.zdetection.api.v1.ZThreatDisposition;
import com.zimperium.zdetection.api.v1.enums.ThreatSeverity;
import com.zimperium.zdetection.api.v1.enums.ZCloudState;
import com.zimperium.zdetection.api.v1.enums.ZEngineState;
import com.zimperium.zdetection.api.v1.siteinsight.VpnNotificationCallback;
import com.zimperium.zdetection.internal.ZDetectionInternal;
import com.zimperium.zdetection.utils.ZipsStatistics;
import com.zimperium.ziap_demo.R;
import com.zimperium.ziap_demo.ZiapApplication;
import com.zimperium.zdetection.api.v1.ZSimulatedAttack;
import com.zimperium.zprotect.ZProtect;
import com.zimperium.zprotect.ZProtectConfig;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * A login screen that offers login via email/password.
 * Just an example of launching into another activity after verifying
 * ziap is fully loaded.
 */
public class MainActivity extends Activity {

    private static void info(String text) {
        Log.i("MainActivity", text);
    }

    private ThreatAdapter threatAdapter;

    final private BroadcastReceiver mMessageReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            //threat was detected.. update the list.
            info("BroadcastReceiver: " + intent);
            new LoadMainContents().execute();
        }
    };


    final Runnable detectionStateUpdate = new Runnable() {
        @Override
        public void run() {

            final TextView message = findViewById(R.id.detection_state);
            if (message != null && ZDetectionInternal.getDetectionState() != null) {
                if (ZDetectionInternal.getDetectionState().cloudState != ZCloudState.RUNNING) {
                    message.setText(ZDetectionInternal.getDetectionState().cloudState.toString());
                } else {
                    message.setText(ZDetectionInternal.getDetectionState().engineState.toString());
                }
                //If not detection, keep updating until it is
                if (ZDetectionInternal.getDetectionState().engineState == ZEngineState.NOT_DETECTING) {
                    message.postDelayed(detectionStateUpdate, 1000);
                }
            }
        }
    };

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        LocalBroadcastManager.getInstance(getApplicationContext()).registerReceiver(mMessageReceiver, new IntentFilter("threat-event"));
        ZProtect zProtect = new ZProtect();

        if (getIntent().getStringExtra("testname") != null)
            if (getIntent().getStringExtra("testname").equals("askvpnpermission")) {
                zProtect.setVpnNotificationCallback(vpnNotificationCallback);
                VPNPermission();
            }


    }

    VpnNotificationCallback vpnNotificationCallback = new VpnNotificationCallback() {
        @Override
        public Notification onVpnNotificationRequired(Context context) {
            createNotificationChannel();
            Notification.Builder builder = new Notification.Builder(context)
                    .setSmallIcon(R.drawable.icon)
                    .setContentTitle("zprotect vpn");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                builder.setChannelId("channelid");
            }
            return builder.build();
        }
    };
    // Set a notification callback (required for android 8+)

    private void createNotificationChannel() {
        // Create the NotificationChannel, but only on API 26+ because
        // the NotificationChannel class is new and not in the support library
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            int importance = NotificationManager.IMPORTANCE_DEFAULT;
            CharSequence name = "Channel name";
            String description = "Channel Desc";
            NotificationChannel channel = new NotificationChannel("channelid", name, importance);
            channel.setDescription(description);
            // Register the channel with the system; you can't change the importance
            // or other notification behaviors after this
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }


    public void VPNPermission() {
        ZProtect zProtect = new ZProtect();
        ZProtectConfig zProtectConfig = ZProtectConfig.createConfigWithCurrentValues();

        if (zProtect.hasVPNAuthorization()) {
            // We already have permission, we can start the VPN
            zProtect.startVPN();
            zProtect.updateConfiguration(zProtectConfig);
//                            Toast.makeText(getApplicationContext(), "Updating Configs after VPN turned on", Toast.LENGTH_SHORT).show();
//            Toast.makeText(getApplicationContext(), "VPN Running : "+zProtect.isVPNRunning(), Toast.LENGTH_SHORT).show();
        } else {
            // No permission, show user a permission popup
            Intent vpnIntent = zProtect.requestVPNAuthorizationFromUser();
            int vpnRequestCode = 1;
            startActivityForResult(vpnIntent, vpnRequestCode);
            System.out.println("Check for VPN Permission screen");
//            Toast.makeText(getApplicationContext(), "VPN Running : "+zProtect.isVPNRunning(), Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        ListView threatListView = findViewById(R.id.threat_list);
        this.threatAdapter = new ThreatAdapter();
        threatListView.setAdapter(this.threatAdapter);
    }

    @Override
    protected void onResume() {
        super.onResume();

        final TextView message = findViewById(R.id.detection_state);
        if (message != null) {
            message.post(detectionStateUpdate);
        }

        final TextView ip = findViewById(R.id.ip_address);
        if (ip != null) {
            WifiManager wm = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
            if (wm != null) {
                int ipAddress = wm.getConnectionInfo().getIpAddress();
                ip.setText(String.format("%d.%d.%d.%d", (ipAddress & 0xff), (ipAddress >> 8 & 0xff), (ipAddress >> 16 & 0xff), (ipAddress >> 24 & 0xff)));
            }
        }

        TextView scanTime = findViewById(R.id.last_scan_time);
        if (scanTime != null) {
            long epoch = new ZThreatDisposition(getApplicationContext()).getLastScanTimestamp();
            String scanDate = (epoch > 0) ? new SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault()).format(new Date(epoch)) : "No scan";

            scanTime.setText(scanDate);
        }


        findViewById(R.id.fake_threat_button).setOnClickListener(
                new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        ZDetection.setTrackingIds("HELLO EMMA!", System.currentTimeMillis() + "");
                        ZSimulatedAttack attack = new ZSimulatedAttack();
                        attack.setGatewayIP("192.0.2.0");
                        attack.setGatewayMAC("02:00:5E:10:00:00:00:00");
                        attack.setIp("192.0.2.24");
                        attack.setMac("02:00:5E:10:00:00:00:FF");
                        new ZDetectionTester().testARPMITMThreat(attack);
                    }

                }
        );

        new LoadMainContents().execute();

    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        LocalBroadcastManager.getInstance(getApplicationContext()).unregisterReceiver(mMessageReceiver);
    }

    /**
     * The background task to load the saved threats from our simple Database
     * and do a rooted and stagefright check.
     */
    private class LoadMainContents extends AsyncTask<Void, Void, Void> {

        List<Threat> threats = new ArrayList<>();
        boolean isRooted = false;

        @Override
        protected Void doInBackground(Void... params) {
            //Load Threat List from Cursor here.
            info("doInBackground()");
            ZThreatDisposition disposition = new ZThreatDisposition(getApplicationContext());
            threats.addAll(disposition.getActiveThreats());

            info("Active Threat Count: " + threats.size());
            for (Threat threat : threats) {
                info("\t" + threat.getHumanThreatName());
            }

            isRooted = disposition.isRooted();
            return null;
        }

        @Override
        protected void onPostExecute(Void result) {

            info("onPostExecute()");

            //In UI thread, set the new list.
            threatAdapter.setThreats(threats);

            setRooted(isRooted);

            ZThreatDisposition disposition = new ZThreatDisposition(getApplicationContext());
            setBackground(disposition.isCompromised());
        }

    }

    protected void setRooted(boolean isRooted) {

        final TextView rooted = findViewById(R.id.rooted_state);
        if (rooted != null) {
            rooted.setText(isRooted ? "Rooted!" : "Not Rooted");
        }
    }

    protected void setBackground(boolean isCompromised) {

        TextView message = findViewById(R.id.main_message);

        if (isCompromised) {
            message.setText("Active Threats Detected!");
        } else {
            message.setText("zIAP is protecting your device.");
        }
    }


    private class ThreatAdapter extends BaseAdapter {

        private ArrayList<Threat> items = new ArrayList<>();

        void setThreats(final List<Threat> threats) {
            items.clear();
            items.addAll(threats);
            notifyDataSetChanged();
        }

        @Override
        public int getCount() {
            return items.size();
        }

        @Override
        public Object getItem(int position) {
            return items.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {

            if (convertView == null) {
                LayoutInflater mInflater = (LayoutInflater) getSystemService(Activity.LAYOUT_INFLATER_SERVICE);
                convertView = mInflater.inflate(R.layout.threat_entry_item, null);
            }

            TextView time = convertView.findViewById(R.id.threat_time);
            TextView title = convertView.findViewById(R.id.threat_title);
            TextView description = convertView.findViewById(R.id.threat_description);

            Threat item = items.get(position);

            time.setText(SimpleDateFormat.getDateTimeInstance().format(new Date(item.getAttackTime())));
            title.setText(item.getHumanThreatName());
            description.setText(item.getHumanThreatSummary());

            if (item.getThreatSeverity() == ThreatSeverity.CRITICAL) {
                convertView.setBackgroundResource(android.R.color.holo_red_light);
            } else {
                convertView.setBackgroundResource(android.R.color.transparent);
            }

            return convertView;
        }
    }
}

