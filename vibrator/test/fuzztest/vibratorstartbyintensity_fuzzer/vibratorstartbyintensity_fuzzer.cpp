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

#include "vibratorstartbyintensity_fuzzer.h"
#include "hdf_base.h"
#include "v1_3/vibrator_interface_proxy.h"
#include <hdf_log.h>
#include <securec.h>

using namespace OHOS::HDI::Vibrator;
using namespace OHOS::HDI::Vibrator::V1_3;

namespace OHOS {
    bool VibratorStartByIntensityFuzzTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr) {
            return false;
        }
        sptr<V1_3::IVibratorInterface> g_vibratorInterface = V1_3::IVibratorInterface::Get();
        int ret = g_vibratorInterface->StartByIntensity(reinterpret_cast<const std::string &>(data), *(uint16_t *)data);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Vibrator StartByIntensity failed, ret is [%{public}x]\n", __func__, ret);
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
    OHOS::VibratorStartByIntensityFuzzTest(data, size);
    return 0;
}

