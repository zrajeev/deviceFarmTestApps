package com.zimperium.ziap_demo;

import android.content.Context;
import android.content.Intent;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.zimperium.ziap_demo.ui.LoadingActivity;
import com.zimperium.ziap_demo.ui.MainActivity;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {
    @Test
    public void useAppContext() {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();

        Intent intent = new Intent(appContext, LoadingActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        appContext.startActivity(intent);
        long stime = System.currentTimeMillis();
        long rTime = TimeUnit.MINUTES.toMillis(10);
        while((System.currentTimeMillis()-stime) < rTime)
        {
            try {
                Thread.sleep(100);
            }catch (Exception e)
            {}
        }
        assertEquals("com.zimperium.ziap_demo", appContext.getPackageName());

    }
}
