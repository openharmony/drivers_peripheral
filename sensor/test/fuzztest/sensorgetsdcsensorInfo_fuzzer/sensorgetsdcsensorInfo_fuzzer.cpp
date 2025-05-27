/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "sensorgetsdcsensorInfo_fuzzer.h"
#include "hdf_base.h"
#include "v3_0/sensor_interface_proxy.h"
#include <hdf_log.h>
#include <securec.h>

using namespace OHOS::HDI::Sensor::V3_0;

namespace {
    struct AllParameters {
        SdcSensorInfo sdcSensorInfo;
    };
}

namespace OHOS {
    bool SensorGetSdcSensorInfoFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        struct AllParameters params;
        sptr<ISensorInterface> g_sensorInterface = ISensorInterface::Get();

        if (size < sizeof(params)) {
            return 0;
        }

        if (memcpy_s(reinterpret_cast<void *>(&params), sizeof(params), data, sizeof(params)) != 0) {
            HDF_LOGE("%{public}s: memcpy_s failed", __func__);
            return false;
        }
        std::vector<SdcSensorInfo> sdcSensorInfos;
        sdcSensorInfos.push_back(std::move(params.sdcSensorInfo));

        if (!g_sensorInterface->GetSdcSensorInfo(sdcSensorInfos)) {
            result = true;
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < sizeof(int32_t)) {
        return 0;
    }
    /* Run your code on data */
    OHOS::SensorGetSdcSensorInfoFuzzTest(data, size);
    return 0;
}

