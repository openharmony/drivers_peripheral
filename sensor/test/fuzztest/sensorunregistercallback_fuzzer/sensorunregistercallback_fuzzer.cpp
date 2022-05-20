/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "sensorunregistercallback_fuzzer.h"
#include "hdf_base.h"
#include "sensor_impl.h"
#include "v1_0/isensor_interface.h"

using namespace OHOS::HDI::Sensor::V1_0;

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V1_0 {
int32_t SensorUnregisterCallbackFuzzer::OnDataEvent(const HdfSensorEvents& event)
{
    (void)event;
    return HDF_SUCCESS;
}
} // V1_0
} // Sensor
} // HDI
} // OHOS

namespace OHOS {
    bool SensorUnregisterCallbackFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        sptr<ISensorInterface> g_sensorInterface = ISensorInterface::Get();
        sptr<ISensorCallback> g_traditionalCallback = new SensorUnregisterCallbackFuzzer();
        if (!g_sensorInterface->Register(*(int32_t *)data, g_traditionalCallback)) {
            result = true;
        }
        if (!g_sensorInterface->Unregister(*(int32_t *)data, g_traditionalCallback)) {
            result = true;
        }
        return result;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SensorUnregisterCallbackFuzzTest(data, size);
    return 0;
}

