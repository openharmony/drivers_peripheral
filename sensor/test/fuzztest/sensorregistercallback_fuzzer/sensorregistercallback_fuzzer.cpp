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

#include "sensorregistercallback_fuzzer.h"
#include "hdf_base.h"
#include "sensor_impl.h"
#include "v1_0/isensor_interface.h"

using namespace OHOS::HDI::Sensor::V1_0;

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V1_0 {
int32_t SensorRegisterCallbackFuzzer::OnDataEvent(const HdfSensorEvents& event)
{
    (void)event;
    return HDF_SUCCESS;
}
} // V1_0
} // Sensor
} // HDI
} // OHOS

namespace OHOS {
    bool SensorRegisterFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        sptr<ISensorInterface> g_sensorInterface = ISensorInterface::Get();
        sptr<ISensorCallback> g_traditionalCallback = new SensorRegisterCallbackFuzzer();
        if (!g_sensorInterface->Register(static_cast<int32_t>(*data), g_traditionalCallback)) {
            result = true;
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SensorRegisterFuzzTest(data, size);
    return 0;
}

