/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "getallvendortags_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "hdf_log.h"
#include "v1_0/icamera_vendor_tag.h"

namespace OHOS {
    bool GetAllVendorTagsFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        auto g_cameraVendorTagService = OHOS::HDI::Camera::Metadata::V1_0::ICameraVendorTag::Get(true);
        std::vector<OHOS::HDI::Camera::Metadata::V1_0::VendorTag> g_hdiTagVec;
        if (!g_cameraVendorTagService->GetAllVendorTags(g_hdiTagVec)) {
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
    OHOS::GetAllVendorTagsFuzzTest(data, size);
    return 0;
}
