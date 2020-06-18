package com.zimperium.ziap_demo;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import androidx.test.InstrumentationRegistry;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject;
import androidx.test.uiautomator.UiObjectNotFoundException;
import androidx.test.uiautomator.UiSelector;
import androidx.test.uiautomator.Until;

import com.zimperium.zdetection.api.v1.DetectionState;
import com.zimperium.zdetection.api.v1.DetectionStateCallback;
import com.zimperium.zdetection.api.v1.Threat;
import com.zimperium.zdetection.api.v1.ThreatCallback;
import com.zimperium.zdetection.api.v1.ThreatType;
import com.zimperium.zdetection.api.v1.ZDetection;

import com.zimperium.zdetection.api.v1.enums.ZCloudState;
import com.zimperium.zdetection.api.v1.enums.ZEngineState;
import com.zimperium.zdetection.api.v1.enums.ZErrorState;
import com.zimperium.ziap_demo.ui.MainActivity;
import com.zimperium.zprotect.ZProtect;

import com.zimperium.ziap_demo.ui.LoadingActivity;

import com.zimperium.zdetection.api.v1.ZThreatDisposition;
import com.zimperium.zprotect.ZProtectConfig;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.URL;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;
import static java.lang.Thread.sleep;
import static org.junit.Assert.assertNotNull;


public class PhishingAutomationTest {

    @Before
    public void setUp(){
        if (Looper.myLooper() == null)
        {
            Looper.prepare();
        }
    }

    private static void allowPermissionsIfNeeded() {
        if (Build.VERSION.SDK_INT >= 23) {
            UiDevice device = UiDevice.getInstance(getInstrumentation());
            UiObject allowPermissions = device.findObject(new UiSelector().text("OK"));
            if (allowPermissions.exists()) {
                try {
                    allowPermissions.click();
                } catch (UiObjectNotFoundException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @Test
    public void StartVPN() throws InterruptedException {
        ZProtect zProtect = new ZProtect();
        ZProtectConfig zProtectConfig = ZProtectConfig.createConfigWithCurrentValues();
        Context appContext = InstrumentationRegistry.getTargetContext();
        ZThreatDisposition disposition = new ZThreatDisposition(appContext.getApplicationContext());
        Intent intent = new Intent(appContext, LoadingActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.putExtra("testname","askvpnpermission");
        appContext.startActivity(intent);


        long stime = System.currentTimeMillis();
        long rTime = TimeUnit.MINUTES.toMillis(1);
        while ((System.currentTimeMillis() - stime) < rTime) {
            try {
                Thread.sleep(100);
            } catch (Exception e) {
            }
        }

        // Give VPN permissions
        allowPermissionsIfNeeded();
        zProtect.updateConfiguration(zProtectConfig);
        zProtect.startVPN();
        Log.d("Phishing", "Started VPN with VPN permissions");
//
//        //Browse through websites
//        Context context = InstrumentationRegistry.getInstrumentation().getContext();
//        Intent intent = context.getPackageManager().getLaunchIntentForPackage("com.android.chrome");
//        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK);
//        intent.setData(Uri.parse("https://stackoverflow.com/"));
//        context.startActivity(intent);
//        mDevice.wait(Until.hasObject(By.pkg("com.android.chrome").depth(0)), TIMEOUT);


        Thread.sleep(5000);


    }
}
