package com.zimperium.ziap_demo;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import androidx.test.InstrumentationRegistry;
import androidx.test.rule.ActivityTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.zimperium.zdetection.api.v1.Threat;
import com.zimperium.zdetection.api.v1.ThreatType;
import com.zimperium.zdetection.api.v1.ZDetection;

import com.zimperium.ziap_demo.ui.MainActivity;
import com.zimperium.zprotect.ZProtect;

import com.zimperium.ziap_demo.ui.LoadingActivity;

import com.zimperium.zdetection.api.v1.ZThreatDisposition;
import com.zimperium.zprotect.ZProtectConfig;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.URL;
import java.util.List;
import java.util.concurrent.TimeUnit;
import androidx.test.rule.GrantPermissionRule;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject;
import androidx.test.uiautomator.UiObjectNotFoundException;
import androidx.test.uiautomator.UiSelector;

import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;
import static com.zimperium.zdetection.api.v1.ThreatType.USB_DEBUGGING_ON;
import static java.lang.Thread.sleep;
import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */


@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {

    @Before
    public void setUp(){
        if (Looper.myLooper() == null)
        {
            Looper.prepare();
        }
    }

    public void runApp(Context appContext){
        appContext = InstrumentationRegistry.getTargetContext();

        Intent intent = new Intent(appContext, LoadingActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        appContext.startActivity(intent);

        long stime = System.currentTimeMillis();
        long rTime = TimeUnit.MINUTES.toMillis(2);
        while((System.currentTimeMillis()-stime) < rTime)
        {
            try {
                sleep(100);
                assertNotNull(ZDetection.getDetectionDetailedInfo(appContext.getApplicationContext()).z9DownloadDate());

            }catch (Exception e)
            {}
        }
    }

    @Test
    public void useAppContext() {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);

        assertEquals("com.zimperium.ziap_demo", appContext.getPackageName());

//        Toast.makeText(appContext.getApplicationContext(), "Tests passed!" , Toast.LENGTH_SHORT).show();

    }

    @Test
    public void checkPrivacyPolicy(){
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);
        //Check for privacy policy downloaded. Will fail if false.
        assertNotNull(ZDetection.getDetectionDetailedInfo(appContext.getApplicationContext()).privacyPolicyDate());
    }

    @Test
    public void checkTRM(){
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);
        //Check for TRM downloaded. Will fail if false.
        assertNotNull(ZDetection.getDetectionDetailedInfo(appContext.getApplicationContext()).threatPolicyDate());

    }

    @Test
    public void checkPhishingPolicy(){
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);
        //Check for privacy policy downloaded. Will fail if false.
        assertNotNull(ZDetection.getDetectionDetailedInfo(appContext.getApplicationContext()).phishingClassifierDownloadDate());

    }

    @Test
    public void checkUSBDebugging(){

        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);
        ZThreatDisposition disposition = new ZThreatDisposition(appContext.getApplicationContext());

        //Check for USB debugging
        List<Threat> threats = disposition.getActiveThreats();
        for (Threat t : threats)
        {
            Log.d( "Threat detected",t.getHumanThreatName());
            if(t.getHumanThreatName() == "USB Debugging Enabled"){
                assertEquals("USB Debugging Enabled", t.getHumanThreatName());
            }
        }
    }

    @Test
    public void checkDeveloperMode(){
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);
        ZThreatDisposition disposition = new ZThreatDisposition(appContext.getApplicationContext());

        //Check for Developer Mode

        List<Threat> threats = disposition.getActiveThreats();
        for (Threat t : threats)
        {
            Log.d( "Threat detected",t.getHumanThreatName());
            if(t.getHumanThreatName() == "Developer Mode Enabled"){
                assertEquals("Developer Mode Enabled", t.getHumanThreatName());
            }
        }
    }

    @Test
    public void checkRooted(){
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);
        ZThreatDisposition disposition = new ZThreatDisposition(appContext.getApplicationContext());


        //Check for Developer Mode

        List<Threat> threats = disposition.getActiveThreats();
        for (Threat t : threats)
        {
            Log.d( "Threat detected",t.getHumanThreatName());
//            if(t.getHumanThreatName() == "Developer Mode Enabled"){
//                assertEquals("Developer Mode Enabled", t.getHumanThreatName());
//            }
        }
    }

//    @Rule
//    public GrantPermissionRule mRuntimePermissionRule = GrantPermissionRule .grant(Manifest.permission.BIND_VPN_SERVICE);

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
    public void askVPNPermission() throws InterruptedException {
        ZProtect zProtect = new ZProtect();
        ZProtectConfig zProtectConfig = ZProtectConfig.createConfigWithCurrentValues();
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);
        ZThreatDisposition disposition = new ZThreatDisposition(appContext.getApplicationContext());

        allowPermissionsIfNeeded();
        zProtect.updateConfiguration(zProtectConfig);
        zProtect.startVPN();

        Thread.sleep(5000);

        // ask for VPN permissions
//        MainActivity mainActivity = new MainActivity();
//        mainActivity.VPNPermission();

    }





}
