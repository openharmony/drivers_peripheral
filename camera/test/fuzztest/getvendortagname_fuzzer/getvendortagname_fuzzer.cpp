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

#include "getvendortagname_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "hdf_log.h"
#include "v1_0/icamera_vendor_tag.h"

namespace OHOS {
    bool GetVendorTagNameFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        auto g_cameraVendorTagService = OHOS::HDI::Camera::Metadata::V1_0::ICameraVendorTag::Get(true);
        void* tagName = nullptr;
        if (!g_cameraVendorTagService->GetVendorTagName(*(uint32_t *)data, tagName)) {
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
    OHOS::GetVendorTagNameFuzzTest(data, size);
    return 0;
}
