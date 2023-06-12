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

#define SIZE_KEY 276
#define SIZE_PARAMSET_INIT 172
#define SIZE_PARAMSET_UPDATE 120
#define SIZE_PARAMSET_FINISH 188
#define ALLSIZE (SIZE_KEY + SIZE_PARAMSET_INIT + SIZE_PARAMSET_UPDATE + SIZE_PARAMSET_FINISH)

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size <= ALLSIZE) {
        return false;
    }

    uint8_t *myData = static_cast<uint8_t *>(malloc(sizeof(uint8_t) * size));
    if (myData == nullptr) {
        return false;
    }

    (void)memcpy_s(myData, size, data, size);

    struct HksBlob key = { SIZE_KEY, myData };
    struct HksParamSet *paramSet = reinterpret_cast<struct HksParamSet *>(myData + SIZE_KEY);
    paramSet->paramSetSize = SIZE_PARAMSET_INIT;
    uint8_t buffer[32];
    struct HksBlob handle = {
        .data = buffer,
        .size = sizeof(buffer)
    };
    
    struct HksBlob inData = { size, myData };
    struct HksParamSet *paramSetUpdate = reinterpret_cast<struct HksParamSet *>(myData + SIZE_KEY + SIZE_PARAMSET_INIT);
    paramSetUpdate->paramSetSize = SIZE_PARAMSET_UPDATE;

    struct HksParamSet *paramSetFinish = reinterpret_cast<struct HksParamSet *>(myData + SIZE_KEY + SIZE_PARAMSET_INIT +
        SIZE_PARAMSET_UPDATE);
    paramSetFinish->paramSetSize = SIZE_PARAMSET_FINISH;
    
#ifdef HUKS_HDI_SOFTWARE
    if (HuksFreshParamSet(paramSetUpdate, false) != 0 || HuksFreshParamSet(paramSetFinish, false) != 0) {
        free(myData);
        return false;
    }
#endif
    uint8_t buffer2[1024];
    struct HksBlob out = {
        .data = buffer2,
        .size = sizeof(buffer2)
    };

    (void)g_instance->HuksHdiInit(&key, paramSet, &handle, &out);
    (void)g_instance->HuksHdiUpdate(&handle, paramSetUpdate, &inData, &out);
    (void)g_instance->HuksHdiFinish(&handle, paramSetFinish, &inData, &out);

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
