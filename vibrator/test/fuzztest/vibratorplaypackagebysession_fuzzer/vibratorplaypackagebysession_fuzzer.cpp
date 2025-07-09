/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "vibratorplaypackagebysession_fuzzer.h"
#include "hdf_base.h"
#include "v2_0/vibrator_interface_proxy.h"
#include <hdf_log.h>
#include <securec.h>

using namespace OHOS::HDI::Vibrator::V2_0;

namespace {
    struct AllParameters {
        int32_t g_vibratorPackagepatternNum;
        int32_t g_vibratorPackagepackageduration;
        int32_t g_hapticPaketTime;
        int32_t g_hapticPaketEventNum;
        enum OHOS::HDI::Vibrator::V2_0::EVENT_TYPE g_eventType;
        int32_t g_eventDuration;
        int32_t g_eventTime;
        int32_t g_eventIntensity;
        int32_t g_eventFrequency;
        int32_t g_eventIndex;
        int32_t g_eventPointNum;
        int32_t g_pointTime;
        int32_t g_pointIntensity;
        int32_t g_pointFrequency;
    };
}

namespace OHOS {
    bool VibratorPlayPackageBySessionTest(const uint8_t* data, size_t size)
    {
        struct AllParameters params;
        if (data == nullptr) {
            return false;
        }
        OHOS::HDI::Vibrator::V2_0::VibratorPackage vibratorPackage;

        if (size < sizeof(params)) {
            return false;
        }

        if (memcpy_s(reinterpret_cast<void *>(&params), sizeof(params), data, sizeof(params)) != 0) {
            HDF_LOGE("%{public}s: memcpy_s failed", __func__);
            return false;
        }

        sptr<OHOS::HDI::Vibrator::V2_0::IVibratorInterface> g_vibratorInterface =
            OHOS::HDI::Vibrator::V2_0::IVibratorInterface::Get();
        
        vibratorPackage.patternNum = params.g_vibratorPackagepatternNum;
        vibratorPackage.packageduration = params.g_vibratorPackagepackageduration;

        OHOS::HDI::Vibrator::V2_0::HapticPaket hapticPaket;
        hapticPaket.time = params.g_hapticPaketTime;
        hapticPaket.eventNum = params.g_hapticPaketEventNum;

        OHOS::HDI::Vibrator::V2_0::HapticEvent hapticEvent;
        hapticEvent.type = params.g_eventType;
        hapticEvent.duration = params.g_eventDuration;
        hapticEvent.time = params.g_eventTime;
        hapticEvent.intensity = params.g_eventIntensity;
        hapticEvent.frequency = params.g_eventFrequency;
        hapticEvent.index = params.g_eventIndex;
        hapticEvent.pointNum = params.g_eventPointNum;

        OHOS::HDI::Vibrator::V2_0::CurvePoint curvePoint;
        curvePoint.time = params.g_pointTime;
        curvePoint.intensity = params.g_pointIntensity;
        curvePoint.frequency = params.g_pointFrequency;
        hapticEvent.points.push_back(std::move(curvePoint));

        hapticPaket.events.push_back(std::move(hapticEvent));
        int32_t ret = !g_vibratorInterface->PlayPackageBySession({-1, 1}, 1, vibratorPackage);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: GetConfig failed, ret is [%{public}x]\n", __func__, ret);
            return false;
        }

        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < sizeof(int32_t)) {
        return 0;
    }
    OHOS::VibratorPlayPackageBySessionTest(data, size);
    return 0;
}

