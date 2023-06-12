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

#include "huks_hdi_fuzzer.h"
#include "huks_hdi_passthrough_adapter.h"
#include "huks_hdi_fuzz_common.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>

struct HuksHdi *g_instance = nullptr;

#define SIZE_ALIAS 16
#define SIZE_KEY 16

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size <= (sizeof(struct HksParamSet) + SIZE_ALIAS + SIZE_KEY)) {
        return false;
    }

    uint8_t *myData = static_cast<uint8_t *>(malloc(sizeof(uint8_t) * size));
    if (myData == nullptr) {
        return false;
    }

    (void)memcpy_s(myData, size, data, size);

    struct HksBlob keyAlias = { SIZE_ALIAS, myData };
    struct HksBlob aesKey = { SIZE_KEY, static_cast<uint8_t *>(myData + SIZE_ALIAS) };
    struct HksParamSet *paramSet = reinterpret_cast<struct HksParamSet *>(myData + SIZE_ALIAS + SIZE_KEY);
    paramSet->paramSetSize = size - (SIZE_ALIAS + SIZE_KEY);

#ifdef HUKS_HDI_SOFTWARE
    if (HuksFreshParamSet(paramSet, false) != 0) {
        free(myData);
        return false;
    }
#endif
    uint8_t buffer[1024];
    struct HksBlob out = {
        .data = buffer,
        .size = sizeof(buffer)
    };
    (void)g_instance->HuksHdiImportKey(&keyAlias, &aesKey, paramSet, &out);

    free(myData);
    return true;
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (InitHuksCoreEngine(&g_instance) != 0) {
        return -1;
    }
    DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
