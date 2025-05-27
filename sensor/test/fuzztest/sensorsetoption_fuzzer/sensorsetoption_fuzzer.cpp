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

#include "sensorsetoption_fuzzer.h"
#include "hdf_base.h"
#include "v3_0/sensor_interface_proxy.h"

using namespace OHOS::HDI::Sensor::V3_0;

namespace OHOS {
    bool SensorSetOptionFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        sptr<ISensorInterface> g_sensorInterface = ISensorInterface::Get();
        
        if (!g_sensorInterface->SetOption({0, *(int32_t *)data, 0, 0}, *(uint32_t *)data)) {
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
    OHOS::SensorSetOptionFuzzTest(data, size);
    return 0;
}

