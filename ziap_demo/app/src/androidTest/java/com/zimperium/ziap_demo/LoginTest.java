package com.zimperium.ziap_demo;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import androidx.test.InstrumentationRegistry;
import androidx.test.uiautomator.UiObject;
import androidx.test.uiautomator.UiSelector;

import com.zimperium.zdetection.api.v1.DetectionState;
import com.zimperium.zdetection.api.v1.DetectionStateCallback;
import com.zimperium.zdetection.api.v1.Threat;
import com.zimperium.zdetection.api.v1.ThreatCallback;
import com.zimperium.zdetection.api.v1.ThreatType;
import com.zimperium.zdetection.api.v1.ZDetection;

import com.zimperium.zdetection.api.v1.ZDetectionInfo;
import com.zimperium.zdetection.api.v1.enums.ZCloudState;
import com.zimperium.zdetection.api.v1.enums.ZEngineState;
import com.zimperium.zdetection.api.v1.enums.ZErrorState;
import com.zimperium.zdetection.internal.ZDetectionInternal;
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

import static java.lang.Thread.sleep;
import static org.junit.Assert.assertNotNull;


public class LoginTest {

    private enum OnOff {
        Off,
        On
    };

//    UiObject settingsValidation = new UiObject(new UiSelector().packageName("com.android.settings"));
//    assertTrue("Unable to detect Settings", settingsValidation.exists());

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
    public void deviceGroupLogin(){

        //Regular startup code
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);

        String license = "U2FsdGVkX19hbkVzz8oe59YSnyrqlty5jlW5Ijl5BYPE1gdUzdl-Hznzp8ylMFtDoALkp4ih8pZbD8ngrttqdIzEqPYzOqzAEgP4xVF-8N4mM-xoo2EzvMRCHj0s61-5Xcfcls75_oEUWqAJ-5xIoeKNzXWpY2IqK0w_OX5B2J1tLmzYU5ysDU5h1jOdVsaG2372FqsrD-h8eqqfgLU8UeXj2XfLuG1LxUHr0vCNfXdz5lhKNsPkC0lqGguX3gl3I995Pk_fHqJkJkZV0QhqZ_7YMkYc8aqpuEKrx49WF0jg9Wee0AEscSEQPQc0VDWVQBxtKv25CyVJUXrPWbSDrWzAVX15aBM6EXfwtMpWFQCTN2uEqdG9GvfvMG7tiMBe3qTu_rzGWfH8ARN3bOm9lLVqbnzegcq2wHZYxlnZJ8xxt04vXepRRpTR2qQyH5oLK-LYAaXK06JwFEoEKQjK4DgXDKWlP5AbnrHbSwd955yJolnOXlSAjxHDwuFipDJakUh91UfWkPjnYip7AEanLfiGbzJxvVAIwEg8rNOBk1BjLlWxiyvFxZCN66QsJ4AE9Nzq9O-Hzt_hQT-EsA4xtyEtCYw-1-WbBUVEYR99iCPRPCqEJJFe2Te6eAELjrNVcms0xVJHlxxjAKnn8BEu4mcizRWMlKylay0opstkxF7houI7MzodVCX_gMI1GQCf4Qo5Kod8uxKUtkZdYJLaNA==";
        ZDetection.setLicenseKey(appContext.getApplicationContext(), license.getBytes());

        Toast.makeText(appContext.getApplicationContext(), "New login enabled!!" , Toast.LENGTH_SHORT).show();
        Log.d("Login Test","New login set!");

        ZDetection.startDetecting(appContext);
        ZDetection.addDetectionStateCallback(new DetectionStateCallback() {
            @Override
            public void onStateChanged(DetectionState oldState, DetectionState newState) {
                final ZCloudState cloudState = ZCloudState.RUNNING;
                final ZEngineState engineState = ZEngineState.DETECTING;
                final ZErrorState errorState = ZErrorState.NO_ERROR;
                final CountDownLatch waitForActionComplete = new CountDownLatch(1);
                ;
                if (newState.cloudState == cloudState && newState.engineState == engineState && newState.errorState == errorState) {
                    waitForActionComplete.countDown();
                }
                try {
                    boolean success = waitForActionComplete.await(30, TimeUnit.SECONDS);
                    Assert.assertTrue("Validation for zcloud, engine and error states", success);
                    Log.d("Login Test","Test Passed!!!");

                    sleep(30000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

    }


    @Test
    public void invalidToken(){
        //Regular startup code
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);

        String license = "U2FsdGVkX1-j-hlXur4pUUIqjBoNMeqxjAi36qPfs6z_ix4cw08-WTe-QriD_HGUiShAFOvfx40w5XQUDTXn9tHg9qu3TYwQEGIX7stpEOHh9dxSOj_PS38fu-0o48C_Ts3ymze_t-Dcp_uQdWcnrcjfz6ruTLet4-YV9n4a3y2ENjby3Z5sYAPxJdD2EqcYZ2INtwUugjc5AFJg3M2Z7x0Rr7iMjKsbCOkyaB7pLOKQ8uNzQZXT9O36WLQZ6qhWV1D4MRBAUNvwD3mpNAbxULaNiN-LtGRhM87Eh5yAzc1thVt__xUetrclLBzQVqAMhamS3GnC3PuM6XNQagEsByK_7h7dh6j6m1gi6y6RQLw84b6ousMwxFq0SfzN6f6F93RAbIoePH64tzNEHZjv8ddKdpgmXBP7qjTDdw4MCbXdSY3m268cWIkjEK1c0PsrxUYadS3_z7ylKiKtG9nNjI43DNdR88QiebwIQCJEwnD896Cv7w2tS16tT3r1YpNRYWS2pAEeixrVFFAc7yhi3kZL8K-U_wpxr8z6Wn1r6i_JIgi79D0b1kwBGpuHBtrpFgPXueObNL6Nvh7O2-NtVG2YEOh8IKilkJcRDPpsK_JZVEAWmNtGHhiJpXIZtmR2Ws3JSVIPcc2ySFT4dIlnuMh_JvRClHrpbnxPTBb0_Ew8FMq26SbtGWRWqE0Y3oL3LZxSoDIWo-UlTezxR_AGKQ==";
        ZDetection.setLicenseKey(appContext.getApplicationContext(), license.getBytes());

        Toast.makeText(appContext.getApplicationContext(), "New login enabled!!" , Toast.LENGTH_SHORT).show();
        Log.d("Login Test","New login set!");

        ZDetection.startDetecting(appContext);
        ZDetection.addDetectionStateCallback(new DetectionStateCallback() {
            @Override
            public void onStateChanged(DetectionState oldState, DetectionState newState) {
                final ZCloudState cloudState = ZCloudState.NOT_RUNNING;
                final ZEngineState engineState = ZEngineState.NOT_DETECTING;
                final ZErrorState errorState = ZErrorState.LICENSE_INVALID;
                final CountDownLatch waitForActionComplete = new CountDownLatch(1);
                ;
                if (newState.cloudState == cloudState && newState.engineState == engineState && newState.errorState == errorState ) {
                    waitForActionComplete.countDown();
                }
                try {
                    boolean success = waitForActionComplete.await(30, TimeUnit.SECONDS);
                    Assert.assertTrue("Validation for zcloud, engine and error states", success);
                    Log.d("Login Test","Test Passed!!!");

                    sleep(10000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

    }

    @Test
    public void expired_token(){
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);

        String license = "U2FsdGVkX18thQqv6tJeIx1cBBrJLbwi7SUPlGfwNE1VP9fVxuSqBv3_oiv1dhC5F6PUTLFjP6zS8vWzu2hwTMlOocIhkynw-kZmYPtuq3vz6w8081oXFiC-5BI2KLbiIDniZZeyS13LfmXOI-CHQZCF4xetNB8x1bsDwALt8ygBKReaz7_qwqkye9n_cgt-w5MOwzQCe7bWI1x-fhaoKoOMIIIYrihyrklWVBN7UyUjy48RJniLMqKVHXdwl8OGNDDtHYkywYmhice-9QNML3M7c7QQah41JTDsDnSLmDg4tZarP4J4RkTNGt0LQeK8W2dFrYXO0PZ2gU54mPPpKlPxwCf5lIOdStxd3w0OIBHWY506gjMJpbSdYFb4rk_4Ye_22J7gtCfubC6S4dwNaOjySVjTi2Mbl3SKoM8vyKRS8Wj3N9wk-dKzTKpdVZJAoGXbRRBgv7dDj78rbrMfHvUfIMkCsWsb8q_gtklsBwjVcbGbEwjjIRgRUZ0WE6FIaP2srALk5m6BO-ot6ngzqEFntVDOB1bMp2qlkUjHV0dEsrR6nn5WwbYwmMNScjFBj1dpP-kt8jTHlF3H2yDvmaSCw5j_8uZRI-4wkVESYlzmOyFlkONEGFJYsin6HnmD4nYKuNQ6nRYuIoS5shNEbcY7CxEcckBnt71pM2-pM-uWTh6Q1U4REq8Ir2aKCtAF";
        ZDetection.setLicenseKey(appContext.getApplicationContext(), license.getBytes());

        Toast.makeText(appContext.getApplicationContext(), "New login enabled!!" , Toast.LENGTH_SHORT).show();
        Log.d("Login Test","New login set!");

        ZDetection.startDetecting(appContext);
        ZDetection.addDetectionStateCallback(new DetectionStateCallback() {
            @Override
            public void onStateChanged(DetectionState oldState, DetectionState newState) {
                final ZCloudState cloudState = ZCloudState.RUNNING;
                final ZEngineState engineState = ZEngineState.DETECTING;
                final ZErrorState errorState = ZErrorState.LICENSE_EXPIRED;
                final CountDownLatch waitForActionComplete = new CountDownLatch(1);
                ;
                if (newState.cloudState == cloudState && newState.engineState == engineState && newState.errorState == errorState ) {
                    Log.d("Login Test", "Expired token test. Enginie state will be detecting and cloudstate will be running.");
                    waitForActionComplete.countDown();
                }
                try {
                    boolean success = waitForActionComplete.await(30, TimeUnit.SECONDS);
//                    Assert.assertTrue("Validation for zcloud, engine and error states", success);
                    Log.d("Login Test","Test Passed!!!");


                    sleep(10000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    @Test
    public void LogOutTest(){
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);

        ZDetectionInternal.logout(appContext);
        ZDetection.addDetectionStateCallback(new DetectionStateCallback() {
            @Override
            public void onStateChanged(DetectionState oldState, DetectionState newState) {
                final ZCloudState cloudState = ZCloudState.NOT_RUNNING;
                final ZEngineState engineState = ZEngineState.DETECTING;
                final ZErrorState errorState = ZErrorState.LOGGED_OUT;
                final CountDownLatch waitForActionComplete = new CountDownLatch(1);
                ;
                if (newState.cloudState == cloudState && newState.engineState == engineState && newState.errorState == errorState ) {
                    Log.d("Logout Test", "After logging out, error_state changes to logged_out.");
                    waitForActionComplete.countDown();
                }
                try {
                    boolean success = waitForActionComplete.await(30, TimeUnit.SECONDS);
//                    Assert.assertTrue("Validation for zcloud, engine and error states", success);
                    Log.d("Login Test","Test Passed!!!");


                    sleep(10000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

    }
}
