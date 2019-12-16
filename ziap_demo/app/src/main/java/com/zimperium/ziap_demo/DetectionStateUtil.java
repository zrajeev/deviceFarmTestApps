package com.zimperium.ziap_demo;

/**
 *
 * Copyright © 2018 Zimperium. All rights reserved.
 *
 */

import com.zimperium.zdetection.api.v1.DetectionState;
import com.zimperium.zdetection.api.v1.enums.ZCloudState;
import com.zimperium.zdetection.api.v1.enums.ZEngineState;
import com.zimperium.zdetection.api.v1.enums.ZErrorState;

public class DetectionStateUtil {
    public static boolean isAuthenticated(DetectionState currentDetectionState) {
        return ( currentDetectionState != null
                && currentDetectionState.cloudState != null
                && currentDetectionState.cloudState == ZCloudState.RUNNING);
    }

    public static boolean isAuthenticating(DetectionState currentDetectionState) {
        return ( currentDetectionState != null
                && currentDetectionState.cloudState != null
                && currentDetectionState.cloudState == ZCloudState.AUTHENTICATING
                && currentDetectionState.errorState == ZErrorState.NO_ERROR );
    }

    public static boolean isDetecting(DetectionState currentDetectionState) {
        return ( currentDetectionState != null
                && currentDetectionState.engineState != null
                && currentDetectionState.engineState == ZEngineState.DETECTING);
    }

    public static boolean hasError(DetectionState currentDetectionState) {
        return ( currentDetectionState != null
                && currentDetectionState.errorState != null
                && currentDetectionState.errorState != ZErrorState.NO_ERROR);
    }


}
