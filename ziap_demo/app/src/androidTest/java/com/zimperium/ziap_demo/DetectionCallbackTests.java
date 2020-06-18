package com.zimperium.ziap_demo;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import androidx.test.InstrumentationRegistry;
import androidx.test.rule.ActivityTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.zimperium.zdetection.api.v1.DetectionStateCallback;
import com.zimperium.zdetection.api.v1.Threat;
import com.zimperium.zdetection.api.v1.ThreatCallback;
import com.zimperium.zdetection.api.v1.ThreatType;
import com.zimperium.zdetection.api.v1.ZDetection;

import com.zimperium.zdetection.api.v1.enums.ZCloudState;
import com.zimperium.zdetection.api.v1.enums.ZEngineState;
import com.zimperium.zdetection.api.v1.enums.ZErrorState;
import com.zimperium.zdetection.internal.ZDetectionInternal;
import com.zimperium.ziap_demo.ui.MainActivity;
import com.zimperium.zprotect.ZProtect;

import com.zimperium.ziap_demo.ui.LoadingActivity;

import com.zimperium.zdetection.api.v1.ZThreatDisposition;
import com.zimperium.zprotect.ZProtectConfig;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.URL;
import java.util.List;
import java.util.concurrent.CountDownLatch;
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


@RunWith(AndroidJUnit4.class)
public class DetectionCallbackTests {

    public Context appContext;
    public CountDownLatch waitForLogin;
    public CountDownLatch waitForLogout;
    public CountDownLatch addDetectionStateCallbackLatch;
    public CountDownLatch removeDetectionStateCallbackLatch;

    @Before
    public void setUp(){
        if (Looper.myLooper() == null)
        {
            Looper.prepare();
        }
        appContext = InstrumentationRegistry.getTargetContext();
        waitForLogin = new CountDownLatch(1);
        waitForLogout = new CountDownLatch(1);
        addDetectionStateCallbackLatch = new CountDownLatch(4);
        removeDetectionStateCallbackLatch = new CountDownLatch(5);
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
    public void testAddingDetectionStateCallback (){
        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);

        String license = "U2FsdGVkX19hbkVzz8oe59YSnyrqlty5jlW5Ijl5BYPE1gdUzdl-Hznzp8ylMFtDoALkp4ih8pZbD8ngrttqdIzEqPYzOqzAEgP4xVF-8N4mM-xoo2EzvMRCHj0s61-5Xcfcls75_oEUWqAJ-5xIoeKNzXWpY2IqK0w_OX5B2J1tLmzYU5ysDU5h1jOdVsaG2372FqsrD-h8eqqfgLU8UeXj2XfLuG1LxUHr0vCNfXdz5lhKNsPkC0lqGguX3gl3I995Pk_fHqJkJkZV0QhqZ_7YMkYc8aqpuEKrx49WF0jg9Wee0AEscSEQPQc0VDWVQBxtKv25CyVJUXrPWbSDrWzAVX15aBM6EXfwtMpWFQCTN2uEqdG9GvfvMG7tiMBe3qTu_rzGWfH8ARN3bOm9lLVqbnzegcq2wHZYxlnZJ8xxt04vXepRRpTR2qQyH5oLK-LYAaXK06JwFEoEKQjK4DgXDKWlP5AbnrHbSwd955yJolnOXlSAjxHDwuFipDJakUh91UfWkPjnYip7AEanLfiGbzJxvVAIwEg8rNOBk1BjLlWxiyvFxZCN66QsJ4AE9Nzq9O-Hzt_hQT-EsA4xtyEtCYw-1-WbBUVEYR99iCPRPCqEJJFe2Te6eAELjrNVcms0xVJHlxxjAKnn8BEu4mcizRWMlKylay0opstkxF7houI7MzodVCX_gMI1GQCf4Qo5Kod8uxKUtkZdYJLaNA==";
        ZDetection.setLicenseKey(appContext.getApplicationContext(), license.getBytes());

        zIAPUtils.startDetection_usingDetectCriticalThreatsMethod(appContext);
        DetectionStateCallback detectionStateCallback_1 = zIAPUtils.getDetectionStateCallback(addDetectionStateCallbackLatch);
        zIAPUtils.addDetectionStateCallback(detectionStateCallback_1);
        zIAPUtils.validate_Cloudstate_Enginestate_And_Errorstate(appContext, waitForLogin, ZCloudState.RUNNING, ZEngineState.DETECTING, ZErrorState.NO_ERROR);
        Assert.assertEquals("Validating detection state callback addition", addDetectionStateCallbackLatch.getCount(), 3);
    }

    @Test
    public  void testRemovingDetectionStateCallback() {

        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);

        String license = "U2FsdGVkX19hbkVzz8oe59YSnyrqlty5jlW5Ijl5BYPE1gdUzdl-Hznzp8ylMFtDoALkp4ih8pZbD8ngrttqdIzEqPYzOqzAEgP4xVF-8N4mM-xoo2EzvMRCHj0s61-5Xcfcls75_oEUWqAJ-5xIoeKNzXWpY2IqK0w_OX5B2J1tLmzYU5ysDU5h1jOdVsaG2372FqsrD-h8eqqfgLU8UeXj2XfLuG1LxUHr0vCNfXdz5lhKNsPkC0lqGguX3gl3I995Pk_fHqJkJkZV0QhqZ_7YMkYc8aqpuEKrx49WF0jg9Wee0AEscSEQPQc0VDWVQBxtKv25CyVJUXrPWbSDrWzAVX15aBM6EXfwtMpWFQCTN2uEqdG9GvfvMG7tiMBe3qTu_rzGWfH8ARN3bOm9lLVqbnzegcq2wHZYxlnZJ8xxt04vXepRRpTR2qQyH5oLK-LYAaXK06JwFEoEKQjK4DgXDKWlP5AbnrHbSwd955yJolnOXlSAjxHDwuFipDJakUh91UfWkPjnYip7AEanLfiGbzJxvVAIwEg8rNOBk1BjLlWxiyvFxZCN66QsJ4AE9Nzq9O-Hzt_hQT-EsA4xtyEtCYw-1-WbBUVEYR99iCPRPCqEJJFe2Te6eAELjrNVcms0xVJHlxxjAKnn8BEu4mcizRWMlKylay0opstkxF7houI7MzodVCX_gMI1GQCf4Qo5Kod8uxKUtkZdYJLaNA==";
        ZDetection.setLicenseKey(appContext.getApplicationContext(), license.getBytes());

        zIAPUtils.startDetection_usingDetectCriticalThreatsMethod(appContext);
        DetectionStateCallback detectionStateCallback_2 = zIAPUtils.getDetectionStateCallback(removeDetectionStateCallbackLatch);
        zIAPUtils.addDetectionStateCallback(detectionStateCallback_2);
        zIAPUtils.validate_Cloudstate_Enginestate_And_Errorstate(appContext, waitForLogin, ZCloudState.RUNNING, ZEngineState.DETECTING, ZErrorState.NO_ERROR);
        zIAPUtils.removeDetectionStateCallback(detectionStateCallback_2);
        Assert.assertEquals("Validating detection state callback removal", removeDetectionStateCallbackLatch.getCount(), 4);

    }

    @Test
    public  void testRemovingDetectionStateCallbackWithoutAddingIt() {

        Context appContext = InstrumentationRegistry.getTargetContext();
        runApp(appContext);

        String license = "U2FsdGVkX19hbkVzz8oe59YSnyrqlty5jlW5Ijl5BYPE1gdUzdl-Hznzp8ylMFtDoALkp4ih8pZbD8ngrttqdIzEqPYzOqzAEgP4xVF-8N4mM-xoo2EzvMRCHj0s61-5Xcfcls75_oEUWqAJ-5xIoeKNzXWpY2IqK0w_OX5B2J1tLmzYU5ysDU5h1jOdVsaG2372FqsrD-h8eqqfgLU8UeXj2XfLuG1LxUHr0vCNfXdz5lhKNsPkC0lqGguX3gl3I995Pk_fHqJkJkZV0QhqZ_7YMkYc8aqpuEKrx49WF0jg9Wee0AEscSEQPQc0VDWVQBxtKv25CyVJUXrPWbSDrWzAVX15aBM6EXfwtMpWFQCTN2uEqdG9GvfvMG7tiMBe3qTu_rzGWfH8ARN3bOm9lLVqbnzegcq2wHZYxlnZJ8xxt04vXepRRpTR2qQyH5oLK-LYAaXK06JwFEoEKQjK4DgXDKWlP5AbnrHbSwd955yJolnOXlSAjxHDwuFipDJakUh91UfWkPjnYip7AEanLfiGbzJxvVAIwEg8rNOBk1BjLlWxiyvFxZCN66QsJ4AE9Nzq9O-Hzt_hQT-EsA4xtyEtCYw-1-WbBUVEYR99iCPRPCqEJJFe2Te6eAELjrNVcms0xVJHlxxjAKnn8BEu4mcizRWMlKylay0opstkxF7houI7MzodVCX_gMI1GQCf4Qo5Kod8uxKUtkZdYJLaNA==";
        ZDetection.setLicenseKey(appContext.getApplicationContext(), license.getBytes());
        zIAPUtils.startDetection_usingDetectCriticalThreatsMethod(appContext);
        DetectionStateCallback detectionStateCallback_3 = zIAPUtils.getDetectionStateCallback(removeDetectionStateCallbackLatch);
        zIAPUtils.validate_Cloudstate_Enginestate_And_Errorstate(appContext, waitForLogin, ZCloudState.RUNNING, ZEngineState.DETECTING, ZErrorState.NO_ERROR);
        zIAPUtils.removeDetectionStateCallback(detectionStateCallback_3);
        Assert.assertEquals("Validating detection state callback removal", removeDetectionStateCallbackLatch.getCount(), 5);

    }

    @After
    public void tearDown() {
        //Shutdown zIAP engine
        ZDetectionInternal.logout(appContext);
        ZDetection.shutdownZIAPEngine();
        zIAPUtils.validate_Cloudstate_Enginestate_And_Errorstate(appContext, waitForLogout, ZCloudState.NOT_RUNNING, ZEngineState.NOT_DETECTING, ZErrorState.LOGGED_OUT);
    }

}
