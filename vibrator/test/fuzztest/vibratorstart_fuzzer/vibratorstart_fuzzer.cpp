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

#include "vibratorstart_fuzzer.h"
#include "hdf_base.h"
#include "v1_1/vibrator_interface_proxy.h"

using namespace OHOS::HDI::Vibrator::V1_1;

namespace OHOS {
    bool VibratorStartFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        sptr<IVibratorInterface> g_vibratorInterface = IVibratorInterface::Get();
        if (!g_vibratorInterface->Start(reinterpret_cast<const std::string &>(data))) {
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
    OHOS::VibratorStartFuzzTest(data, size);
    return 0;
}
