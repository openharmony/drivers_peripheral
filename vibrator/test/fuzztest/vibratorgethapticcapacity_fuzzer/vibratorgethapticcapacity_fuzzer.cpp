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

#include "vibratorgethapticcapacity_fuzzer.h"
#include "hdf_base.h"
#include "v2_0/vibrator_interface_proxy.h"
#include <hdf_log.h>
#include <securec.h>

using namespace OHOS::HDI::Vibrator::V2_0;

namespace {
    struct AllParameters {
        OHOS::HDI::Vibrator::V2_0::HapticCapacity hapticCapacity;
    };
}

namespace OHOS {
    bool VibratorGetHapticCapacityTest(const uint8_t* data, size_t size)
    {
        struct AllParameters params;
        if (data == nullptr) {
            return false;
        }

        if (size < sizeof(params)) {
            return false;
        }

        if (memcpy_s(reinterpret_cast<void *>(&params), sizeof(params), data, sizeof(params)) != 0) {
            HDF_LOGE("%{public}s: memcpy_s failed", __func__);
            return false;
        }

        sptr<OHOS::HDI::Vibrator::V2_0::IVibratorInterface> g_vibratorInterface =
            OHOS::HDI::Vibrator::V2_0::IVibratorInterface::Get();
        int32_t ret = !g_vibratorInterface->GetHapticCapacity({-1, 1}, params.hapticCapacity);
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
    OHOS::VibratorGetHapticCapacityTest(data, size);
    return 0;
}

