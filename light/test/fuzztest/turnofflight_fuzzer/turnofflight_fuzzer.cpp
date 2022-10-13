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

#include "turnofflight_fuzzer.h"
#include "hdf_base.h"
#include "light_interface_impl.h"
#include "v1_0/light_interface_proxy.h"

using namespace OHOS::HDI::Light::V1_0;

namespace OHOS {
bool TurnOffLightFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    sptr<ILightInterface> g_lightInterface = ILightInterface::Get();

    if (!g_lightInterface->TurnOnLight(*static_cast<int32_t *>(data), reinterpret_cast<const HdfLightEffect &>(data))) {
        result = true;
    }

    if (!g_lightInterface->TurnOffLight(*static_cast<int32_t *>(data))) {
        result = true;
    }
    return result;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::TurnOffLightFuzzTest(data, size);
    return 0;
}
