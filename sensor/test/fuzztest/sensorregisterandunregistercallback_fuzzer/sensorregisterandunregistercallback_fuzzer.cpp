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

#include "sensorregisterandunregistercallback_fuzzer.h"
#include "hdf_base.h"
#include "v3_0/isensor_interface.h"

using namespace OHOS::HDI::Sensor;
using namespace OHOS::HDI::Sensor::V3_0;

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {
int32_t SensorRegisterAndUnregisterCallbackFuzzer::OnDataEvent(const HdfSensorEvents& event)
{
    (void)event;
    return HDF_SUCCESS;
}
} // V3_0
} // Sensor
} // HDI
} // OHOS

namespace OHOS {
    bool SensorRegisterAndUnregisterCallbackFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        int32_t ret;
        sptr<ISensorInterface> sensorInterface = ISensorInterface::Get();
        sptr<V3_0::ISensorCallback> registerCallback = new SensorRegisterAndUnregisterCallbackFuzzer();
        if (registerCallback == nullptr) {
            return false;
        }
        ret = sensorInterface->Register(*(int32_t *)data, registerCallback);
        if (ret != HDF_SUCCESS) {
            registerCallback = new SensorRegisterAndUnregisterCallbackFuzzer();
            if (registerCallback == nullptr) {
                return false;
            }
        }

        ret = sensorInterface->Unregister(*(int32_t *)data, registerCallback);
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
    OHOS::SensorRegisterAndUnregisterCallbackFuzzTest(data, size);
    return 0;
}

