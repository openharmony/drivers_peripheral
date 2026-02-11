/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "sensorenablewithcallbackid_fuzzer.h"
#include "hdf_base.h"
#include "v3_0/sensor_interface_proxy.h"
#include "v3_1/sensor_interface_proxy.h"
#include "sensor_callback_impl.h"

using namespace OHOS::HDI::Sensor::V3_0;
using OHOS::HDI::Sensor::V3_1::GPS_CALLBACK_ID_BEGIN;

int32_t SensorCallbackImpl::sensorDataCount = 0;
int32_t SensorCallbackImpl::sensorDataCountOld = 0;
bool SensorCallbackImpl::printDataFlag = false;
namespace OHOS {
    bool SensorEnableFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        sptr<OHOS::HDI::Sensor::V3_1::ISensorInterface> g_sensorInterface =
            OHOS::HDI::Sensor::V3_1::ISensorInterface::Get();
        sptr<ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
        if (!g_sensorInterface->EnableWithCallbackId({0, *(int32_t *)data, 0, 0}, GPS_CALLBACK_ID_BEGIN)) {
            result = true;
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
    OHOS::SensorEnableFuzzTest(data, size);
    return 0;
}

