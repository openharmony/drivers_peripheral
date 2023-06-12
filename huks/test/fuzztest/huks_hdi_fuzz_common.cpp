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

#include <securec.h>

#include "huks_hdi_fuzz_common.h"

#define HKS_TAG_TYPE_MASK (0xF << 28)
#define HKS_TAG_TYPE_BYTES (5 << 28)

int32_t InitHuksCoreEngine(struct HuksHdi **coreEngine)
{
    if (coreEngine == nullptr) {
        return -1;
    }
    if (*coreEngine != nullptr) {
        return 0;
    }
    int ret = HuksInitHuksCoreEngine();
    if (ret == 0) {
        struct HuksHdi *instance = HuksGetCoreEngine();
        if (instance->HuksHdiModuleInit() == 0) {
            *coreEngine = instance;
            return 0;
        }
    }
    return -1;
}

static uint32_t GetTagType(uint32_t tag)
{
    return (tag & (uint32_t)HKS_TAG_TYPE_MASK);
}

static inline bool IsAdditionOverflow(uint32_t a, uint32_t b)
{
    return (UINT32_MAX - a) < b;
}

int32_t HuksFreshParamSet(struct HksParamSet *paramSet, bool isCopy)
{
    uint32_t size = paramSet->paramSetSize;
    uint32_t offset = sizeof(struct HksParamSet) + sizeof(struct HksParam) * paramSet->paramsCnt;

    for (uint32_t i = 0; i < paramSet->paramsCnt; i++) {
        if (offset > size) {
            return HUKS_FAILURE;
        }
        if (GetTagType(paramSet->params[i].tag) == HKS_TAG_TYPE_BYTES) {
            if (IsAdditionOverflow(offset, paramSet->params[i].blob.size)) {
                return HUKS_FAILURE;
            }

            if (isCopy && (memcpy_s((uint8_t *)paramSet + offset, size - offset,
                paramSet->params[i].blob.data, paramSet->params[i].blob.size) != EOK)) {
                return HUKS_FAILURE;
            }
            paramSet->params[i].blob.data = (uint8_t *)paramSet + offset;
            offset += paramSet->params[i].blob.size;
        }
    }

    if (paramSet->paramSetSize != offset) {
        return HUKS_FAILURE;
    }
    return HUKS_SUCCESS;
}