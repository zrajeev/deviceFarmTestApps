package com.zimperium.ziap_demo;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;

import com.zimperium.zdetection.api.v1.DetectionState;
import com.zimperium.zdetection.api.v1.DetectionStateCallback;
import com.zimperium.zdetection.api.v1.Threat;
import com.zimperium.zdetection.api.v1.ThreatCallback;
import com.zimperium.zdetection.api.v1.ThreatType;
import com.zimperium.zdetection.api.v1.ZDetection;
import com.zimperium.zdetection.api.v1.ZDetectionTester;
import com.zimperium.zdetection.api.v1.ZSimulatedAttack;
import com.zimperium.zdetection.api.v1.ZThreatDisposition;
import com.zimperium.zdetection.api.v1.enums.ZCloudState;
import com.zimperium.zdetection.api.v1.enums.ZEngineState;
import com.zimperium.zdetection.api.v1.enums.ZErrorState;
import com.zimperium.zdetection.api.v1.enums.ZLogLevel;
import com.zimperium.zdetection.api.v1.malware.MaliciousAppInfo;
import com.zimperium.zdetection.api.v1.malware.MalwareScanCallback;
import com.zimperium.zdetection.api.v1.siteinsight.UrlScanResultIF;
import com.zimperium.zdetection.internal.ZDetectionInternal;

import junit.framework.Assert;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static java.lang.Thread.sleep;

public class zIAPUtils {

    public static void setMDMId(String mdmId) {

        ZDetection.setMdmId(mdmId);

    }

    public static void setDeviceId(String deviceId) {

        ZDetection.setDeviceId(deviceId);

    }

    public static void setLicenseKey_usingOldMethod(byte[] licenseKey, boolean force) {

        ZDetection.setLicenseKey(licenseKey, force);

    }

    public static void setLicenseKey_usingNewMethod(Context appContext, byte[] licenseKey) {

        ZDetection.setLicenseKey(appContext, licenseKey);

    }

    public static void changeLicenseKeyMethod(Context appContext, byte[] licenseKey) {

        ZDetection.changeLicenseKey(appContext, licenseKey);

    }

    public static void startDetection_withoutCallback(Context appContext) {

        ZDetection.startDetecting(appContext);

    }

    public static void startDetection_usingDetectCriticalThreatsMethod(Context appContext) {

        ZDetection.detectCriticalThreats(appContext, new ThreatCallback() {
            @Override
            public void onThreat(Uri threatUri, Threat threat) {
                System.out.println("Threat: " + threat.getThreatType());
                System.out.println("Alert: " + threat.getAlertText());
            }
        });

    }

    public static void startDetection_usingDetectCriticalThreatsMethod(Context appContext, ThreatCallback threatCallback) {

        ZDetection.detectCriticalThreats(appContext, threatCallback);

    }

    public static void startDetection_usingDetectRougeSSLCert (Context appContext) {

        ZDetection.detectRogueSSLCert(appContext, new ThreatCallback() {
            @Override
            public void onThreat(Uri threatUri, Threat threat) {
                System.out.println("Threat: " + threat.getThreatType());
                System.out.println("Alert: " + threat.getAlertText());
            }
        });

    }

    public static void startDetection_usingDetectRougeSSLCert (Context appContext, ThreatCallback threatCallback) {

        ZDetection.detectRogueSSLCert(appContext, threatCallback);

    }

    public static void startDetection_usingDetectRogueNetwork (Context appContext) {

        ZDetection.detectRogueNetwork(appContext, new ThreatCallback() {
            @Override
            public void onThreat(Uri threatUri, Threat threat) {
                System.out.println("Threat: " + threat.getThreatType());
                System.out.println("Alert: " + threat.getAlertText());
            }
        });

    }

    public static void startDetection_usingDetectRogueNetwork_withCallback (Context appContext, ThreatCallback threatCallback) {

        ZDetection.detectRogueNetwork(appContext, threatCallback);

    }

    public static void startDetection_usingDetectDeviceCompromised (Context appContext) {

        ZDetection.detectDeviceCompromised(appContext, new ThreatCallback() {
            @Override
            public void onThreat(Uri threatUri, Threat threat) {
                System.out.println("Threat: " + threat.getThreatType());
                System.out.println("Alert: " + threat.getAlertText());
            }
        });

    }

    public static void startDetection_usingDetectDeviceCompromised_withCallback (Context appContext, ThreatCallback threatCallback) {

        ZDetection.detectDeviceCompromised(appContext, threatCallback);

    }

    public static void startDetection_usingDetectMaliciousApp (Context appContext) {

        ZDetection.detectMaliciousApp(appContext, new ThreatCallback() {
            @Override
            public void onThreat(Uri threatUri, Threat threat) {
                System.out.println("Threat: " + threat.getThreatType());
                System.out.println("Alert: " + threat.getAlertText());
            }
        });

    }

    public static void startDetection_usingDetectMaliciousApp_withCallback (Context appContext, ThreatCallback threatCallback) {

        ZDetection.detectMaliciousApp(appContext, threatCallback);

    }

    public static void startDetection_usingDetectAllThreats (Context appContext) {

        ZDetection.detectAllThreats(appContext, new ThreatCallback() {
            @Override
            public void onThreat(Uri threatUri, Threat threat) {
                System.out.println("Threat: " + threat.getThreatType());
                System.out.println("Alert: " + threat.getAlertText());
            }
        });

    }

    public static void startDetection_usingDetectAllThreats_withCallback (Context appContext, ThreatCallback threatCallback) {

        ZDetection.detectAllThreats(appContext, threatCallback);

    }

    public static void stopDetection_usingThreatCallback (ThreatCallback callback) {

        ZDetection.stopDetecting(callback);

    }

    public static void validate_Cloudstate_Enginestate_And_Errorstate (Context appContext, final CountDownLatch waitForActionComplete,
                                                                       final ZCloudState cloudState, final ZEngineState engineState,
                                                                       final ZErrorState errorState) {

        ZDetection.addDetectionStateCallback(new DetectionStateCallback() {
            @Override
            public void onStateChanged(DetectionState oldState, DetectionState newState) {
                if (newState.cloudState == cloudState && newState.engineState == engineState && newState.errorState == errorState) {
                    waitForActionComplete.countDown();
                }
            }
        });

        try {
            boolean success = waitForActionComplete.await(30, TimeUnit.SECONDS);
            Assert.assertEquals("Validation for zcloud, engine and error states", success, true);
            sleep(30000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

    }

    public static ThreatCallback getNewThreatCallback() {

        return new ThreatCallback() {
            @Override
            public void onThreat(Uri threatUri, Threat threat) {
                System.out.println("###################### Threat Callback HumanThreatType : " + threat.getHumanThreatType() + " ############################");
                System.out.println("###################### Threat Callback HumanThreatName : " + threat.getHumanThreatName() + " ############################");
                System.out.println("###################### Threat Callback ThreatType      : " + threat.getThreatType() + " ############################");
                System.out.println("###################### Threat Callback ThreatSeverity  : " + threat.getThreatSeverity() + " ############################");
                System.out.println("###################### Threat Callback isMitigated     : " + threat.isMitigated() + " ############################");
                System.out.println("###################### Threat Callback isSimulated     : " + threat.isSimulated() + " ############################");
                System.out.println("###################### Threat Callback ThreatUUID      : " + threat.getThreatUUID() + " ############################");
                System.out.println("###################### Threat Callback ThreatCategory  : " + threat.getThreatCategory() + " ############################");
            }
        };

    }

    public static ThreatCallback getNewThreatCallback_withLatch(final CountDownLatch countDownLatch) {

        return new ThreatCallback() {
            @Override
            public void onThreat(Uri threatUri, Threat threat) {

                System.out.println("###################### Threat Callback HumanThreatType : " + threat.getHumanThreatType() + " ############################");
                System.out.println("###################### Threat Callback HumanThreatName : " + threat.getHumanThreatName() + " ############################");
                System.out.println("###################### Threat Callback ThreatType      : " + threat.getThreatType() + " ############################");
                System.out.println("###################### Threat Callback ThreatSeverity  : " + threat.getThreatSeverity() + " ############################");
                System.out.println("###################### Threat Callback isMitigated     : " + threat.isMitigated() + " ############################");
                System.out.println("###################### Threat Callback isSimulated     : " + threat.isSimulated() + " ############################");
                System.out.println("###################### Threat Callback ThreatUUID      : " + threat.getThreatUUID() + " ############################");
                System.out.println("###################### Threat Callback ThreatCategory  : " + threat.getThreatCategory() + " ############################");

                countDownLatch.countDown();
            }
        };

    }

    public static void setSafeTrackingIDs_usingNewMethod (String trackingID_1, String trackingID_2) {

        ZDetection.setSafeTrackingIds(trackingID_1, trackingID_2);

    }

    public static void setTrackingIDs_usingOldMethod (String trackingID_1, String trackingID_2) {

        ZDetection.setTrackingIds(trackingID_1, trackingID_2);

    }

    public static void setCustomTags_usingOldMethod (String trackingID_1, String trackingID_2) {

        ZDetection.setCustomTags(trackingID_1, trackingID_2);

    }

    /*
        This method will create a detection state callback
     */
    public static DetectionStateCallback getDetectionStateCallback(final CountDownLatch countDownLatch) {
        return new DetectionStateCallback() {
            @Override
            public void onStateChanged(DetectionState oldDetectionState, DetectionState newDetectionState) {
                System.out.println("\n  ############## DetectionState Callback - Cloud old State = "+oldDetectionState.cloudState+" ################");
                System.out.println("\n  ############## DetectionState Callback - Engine old State = "+oldDetectionState.engineState+" ################");
                System.out.println("\n  ############## DetectionState Callback - Error old State = "+oldDetectionState.errorState+" ################");

                System.out.println("\n  ############## DetectionState Callback - Cloud new State = "+newDetectionState.cloudState+" ################");
                System.out.println("\n  ############## DetectionState Callback - Engine new State = "+newDetectionState.engineState+" ################");
                System.out.println("\n  ############## DetectionState Callback - Error new State = "+newDetectionState.errorState+" ################");

                System.out.println("Counting down "+countDownLatch.toString()+" from "+countDownLatch.getCount()+" to value - 1");
                countDownLatch.countDown();
            }
        };
    }

    public static void addDetectionStateCallback(DetectionStateCallback detectionStateCallback) {

        ZDetection.addDetectionStateCallback(detectionStateCallback);

    }

    public static void removeDetectionStateCallback(DetectionStateCallback detectionStateCallback) {

        ZDetection.removeDetectionStateCallback(detectionStateCallback);

    }

    public static void shutdownZIAPEngine() {

        ZDetection.shutdownZIAPEngine();

    }

    public static ZDetectionTester createNewZDetectionTester() {

        return ZDetection.createZDetectionTester();

    }

    public static ZSimulatedAttack createNewZSimulatedAttack (String gatewayIp, String gatewayMac, String ip, String mac) {

        ZSimulatedAttack zSimulatedAttack = new ZSimulatedAttack();

        zSimulatedAttack.setGatewayIP(gatewayIp);
        zSimulatedAttack.setGatewayMAC(gatewayMac);
        zSimulatedAttack.setIp(ip);
        zSimulatedAttack.setMac(mac);

        return zSimulatedAttack;

    }

    public static Map<String, String> getZSimulatedAttackDetails (ZSimulatedAttack zSimulatedAttack) {
        Map<String, String> attackDetails = new HashMap<String, String>();

        attackDetails.put("gatewayIP",zSimulatedAttack.getGatewayIP());
        attackDetails.put("gatewayMac",zSimulatedAttack.getGatewayMAC());
        attackDetails.put("IP",zSimulatedAttack.getIp());
        attackDetails.put("Mac",zSimulatedAttack.getMac());

        return attackDetails;

    }

    public static void createNewThreat(ZDetectionTester zDetectionTester, ThreatType threatType) {

        zDetectionTester.testThreatWithThreatType(threatType);

    }

    public static List<Threat> getAllActiveThreatDetails(Context context) {

        ZThreatDisposition zThreatDisposition = new ZThreatDisposition(context);

        return zThreatDisposition.getActiveThreats();

    }

    public static void printAllActiveThreatDetails(Context context) {

        List<Threat> activeThreats = getAllActiveThreatDetails(context);

        Iterator itr = activeThreats.iterator();

        System.out.println("************************* START - PRINT ALL THREAT DETAILS *************************#");

        while (itr.hasNext()){

            Threat threat = (Threat)itr.next();
            System.out.println("###################### START - THREAT DETAILS ############################");
            System.out.println("###################### HumanThreatType : " + threat.getHumanThreatType() + " ############################");
            System.out.println("###################### HumanThreatName : " + threat.getHumanThreatName() + " ############################");
            System.out.println("###################### ThreatType      : " + threat.getThreatType() + " ############################");
            System.out.println("###################### ThreatSeverity  : " + threat.getThreatSeverity() + " ############################");
            System.out.println("###################### isMitigated     : " + threat.isMitigated() + " ############################");
            System.out.println("###################### isSimulated     : " + threat.isSimulated() + " ############################");
            System.out.println("###################### ThreatUUID      : " + threat.getThreatUUID() + " ############################");
            System.out.println("###################### ThreatCategory  : " + threat.getThreatCategory() + " ############################");
            System.out.println("###################### END - THREAT DETAILS ############################");

        }

        System.out.println("************************* END - PRINT ALL THREAT DETAILS *************************");

    }

    public static boolean checkIfThreatDetected(Context context, ThreatType threatType) {

        List<Threat> activeThreats = getAllActiveThreatDetails(context);

        Iterator itr = activeThreats.iterator();

        while (itr.hasNext()){
            Threat threat = (Threat)itr.next();

            if (threat.getThreatType().equals(threatType))
                return true;
        }

        return false;

    }

    public static void removeAllSimulatedThreats(ZDetectionTester zDetectionTester, Context context) {

        zDetectionTester.removeAllSimulatedThreats(context);

    }

    public static void generateLogs(Context appContext) {

        ZDetectionInternal.log(appContext, ZLogLevel.DEBUG, "1. Wilson is giving you a debug msg");
        ZDetectionInternal.log(appContext, ZLogLevel.DEBUG, "2. Wilson is giving you a debug msg");
        ZDetectionInternal.log(appContext, ZLogLevel.DEBUG, "3. Wilson is giving you a debug msg");
        ZDetectionInternal.log(appContext, ZLogLevel.DEBUG, "4. Wilson is giving you a debug msg");
        ZDetectionInternal.log(appContext, ZLogLevel.DEBUG, "5. Wilson is giving you a debug msg");

        ZDetectionInternal.log(appContext, ZLogLevel.WARNING, "1. Wilson is giving you a warning");
        ZDetectionInternal.log(appContext, ZLogLevel.WARNING, "2. Wilson is giving you a warning");
        ZDetectionInternal.log(appContext, ZLogLevel.WARNING, "3. Wilson is giving you a warning");
        ZDetectionInternal.log(appContext, ZLogLevel.WARNING, "4. Wilson is giving you a warning");
        ZDetectionInternal.log(appContext, ZLogLevel.WARNING, "5. Wilson is giving you a warning");

    }

    public static MalwareScanCallback createNewMalwareScanCallback (final List<MaliciousAppInfo> maliciousApps, final CountDownLatch waitForScanComplete, final String logPrefix) {

        return new MalwareScanCallback() {
            long scanStartTime;
            long scanEndTime;
            int totalApps;

            @Override
            public void onScanStart(int i) {

                log(logPrefix, "Starting Malware Scan - Total count of apps : " + i);
                scanStartTime = System.currentTimeMillis();
                totalApps = i;

            }

            @Override
            public void onScanProgress(int i, String packageName) {

                log(logPrefix, "Scanning in progress - Completed : " + i + " out of " + totalApps + " apps, package name - " + packageName);

            }

            @Override
            public void onMaliciousApp(MaliciousAppInfo maliciousAppInfo) {

                maliciousApps.add(maliciousAppInfo);

                log(logPrefix, "Found Malicious app - appHash          :" + maliciousAppInfo.apkHash);
                log(logPrefix, "Found Malicious app - apkSource        :" + maliciousAppInfo.apkSource);
                log(logPrefix, "Found Malicious app - appName          :" + maliciousAppInfo.appName);
                log(logPrefix, "Found Malicious app - appPath          :" + maliciousAppInfo.appPath);
                log(logPrefix, "Found Malicious app - malwareName      :" + maliciousAppInfo.malwareName);
                log(logPrefix, "Found Malicious app - packageName      :" + maliciousAppInfo.packageName);
                log(logPrefix, "Found Malicious app - appRiskScale     :" + maliciousAppInfo.appRiskScale);
                log(logPrefix, "Found Malicious app - detectedLocally  :" + maliciousAppInfo.detectedLocally);

            }

            @Override
            public void onScanComplete() {

                log(logPrefix, "Malware Scanning Complete");
                waitForScanComplete.countDown();
                scanEndTime = System.currentTimeMillis();
                log(logPrefix, "Total time for scan to complete was : " + (scanEndTime - scanStartTime) +" milli seconds or " + ((double)(scanEndTime - scanStartTime)/60000) + " minutes");

            }

            @Override
            public void onScanError(Exception e) {

                log(logPrefix, "Error occured while scanning - "+ e.getMessage());
                e.printStackTrace();

            }
        };
    }

    public static void printAllMaliciousAppsFound(List<MaliciousAppInfo> maliciousApps, String logPrefix) {

        log(logPrefix, "Total malicious apps found = " + maliciousApps.size());

        log(logPrefix, "========================= START : Malicious App Info =============================");

        if (maliciousApps.size() > 0) {
            for(MaliciousAppInfo maliciousAppInfo : maliciousApps) {

                log(logPrefix, "Found Malicious app - appHash          :" + maliciousAppInfo.apkHash);
                log(logPrefix, "Found Malicious app - apkSource        :" + maliciousAppInfo.apkSource);
                log(logPrefix, "Found Malicious app - appName          :" + maliciousAppInfo.appName);
                log(logPrefix, "Found Malicious app - appPath          :" + maliciousAppInfo.appPath);
                log(logPrefix, "Found Malicious app - malwareName      :" + maliciousAppInfo.malwareName);
                log(logPrefix, "Found Malicious app - packageName      :" + maliciousAppInfo.packageName);
                log(logPrefix, "Found Malicious app - appRiskScale     :" + maliciousAppInfo.appRiskScale);
                log(logPrefix, "Found Malicious app - detectedLocally  :" + maliciousAppInfo.detectedLocally);
                log(logPrefix, "===========================================================================");

            }
        } else {

            log(logPrefix, "There are no malicious apps found for this device");

        }

        log(logPrefix, "========================= END : Malicious App Info =============================");

    }

    public static void log (String prefix, String message) {

        System.out.println(prefix+" "+message);

    }

    public static UrlScanResultIF verifyURLScanResultUsingCallback(final String scanURL, final boolean safe) {

        return new UrlScanResultIF() {
            @Override
            public void onResult(List<String> list, List<String> list1) {
                int flag=0;
                System.out.println("SiteInsiteUrlScan: Safe URLs are:");
                for(String url : list) {
                    System.out.println("SiteInsiteUrlScan: SAFE URL: " + url);
                    if (scanURL.equals(url)){
                        flag++;
                        if(safe)
                            org.junit.Assert.assertEquals("SiteInsiteUrlScan: Safe URL didn't match with input URL", scanURL, url);
                        else
                            org.junit.Assert.assertNotEquals("SiteInsiteUrlScan: This URL should be flagged", scanURL, url);
                    }

                }

                System.out.println("SiteInsiteUrlScan: Flagged URLs are:");
                for(String url : list1) {
                    System.out.println("SiteInsiteUrlScan: FLAGGED URL: " + url);
                    if (scanURL.equals(url)) {
                        flag++;
                        if(!safe)
                            org.junit.Assert.assertEquals("SiteInsiteUrlScan: Flagged URL didn't match with input URL", scanURL, url);
                        else
                            org.junit.Assert.assertNotEquals("SiteInsiteUrlScan: This URL should not be flagged", scanURL, url);
                    }

                }

                org.junit.Assert.assertNotEquals("SiteInsiteUrlScan: URL was found in safe as well as flagged lists.", true, flag>=2);
                org.junit.Assert.assertNotEquals("SiteInsiteUrlScan: URL was not found in the returned results.", true, flag<=0);

            }

            @Override
            public void onError(Exception e) {
                e.printStackTrace();
                org.junit.Assert.fail("SiteInsiteUrlScan: Error occured while scanning urls");
            }

        };

    }

}
