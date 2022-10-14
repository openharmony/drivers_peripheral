/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "displayallocmem_fuzzer.h"
#include "buffer_handle.h"
#include "display_gralloc_client.h"

using namespace OHOS::HDI::Display::V1_0;

namespace OHOS {
    bool DisplayAllocMemFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        static AllocInfo info = {
            .width = *(reinterpret_cast<int32_t *>(const_cast<uint8_t *>(data))),
            .height = *(reinterpret_cast<int32_t *>(const_cast<uint8_t *>(data))),
        };
        BufferHandle *handle = nullptr;
        int32_t ret = IDisplayGralloc::Get()->AllocMem(info, handle);
        if (!ret) {
            result = true;
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DisplayAllocMemFuzzTest(data, size);
    return 0;
}

