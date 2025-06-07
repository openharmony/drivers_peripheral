/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "sensorregisterasyncandunregisterasynccallback_fuzzer.h"
#include "hdf_base.h"
#include "v3_0/isensor_interface.h"
#include <hdf_log.h>

using namespace OHOS::HDI::Sensor;
using namespace OHOS::HDI::Sensor::V3_0;

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {
int32_t SensorRegisterAsyncAndUnregisterAsyncCallbackFuzzer::OnDataEvent(const HdfSensorEvents& event)
{
    HDF_LOGI("%{public}s: sensorId=%{public}d", __func__, event.deviceSensorInfo.sensorType);
    (void)event;
    return HDF_SUCCESS;
}

int32_t SensorRegisterAsyncAndUnregisterAsyncCallbackFuzzer::OnDataEventAsync(
    const std::vector<HdfSensorEvents>& events)
{
    HDF_LOGI("%{public}s: sensorId=%{public}d, timestamp=%{public}s", __func__,
        events[0].deviceSensorInfo.sensorType, std::to_string(events[0].timestamp).c_str());
    (void)events;
    return HDF_SUCCESS;
}
} // V3_0
} // Sensor
} // HDI
} // OHOS

namespace OHOS {
    bool SensorRegisterAsyncAndUnregisterAsyncCallbackFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        int32_t ret;
        sptr<V3_0::ISensorInterface> sensorInterface = V3_0::ISensorInterface::Get();
        sptr<V3_0::ISensorCallback> registerAsyncCallback = new SensorRegisterAsyncAndUnregisterAsyncCallbackFuzzer();
        if (registerAsyncCallback == nullptr) {
            return false;
        }
        ret = sensorInterface->RegisterAsync(*(int32_t *)data, registerAsyncCallback);
        if (ret != HDF_SUCCESS) {
            registerAsyncCallback = new SensorRegisterAsyncAndUnregisterAsyncCallbackFuzzer();
            if (registerAsyncCallback == nullptr) {
                return false;
            }
        }

        ret = sensorInterface->UnregisterAsync(*(int32_t *)data, registerAsyncCallback);
        if (ret == HDF_SUCCESS) {
            return true;
        }
        return result;
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
    OHOS::SensorRegisterAsyncAndUnregisterAsyncCallbackFuzzTest(data, size);
    return 0;
}

