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

#include "effect_common.h"
#include <cstddef>
#include <osal_mem.h>

static const int32_t HDF_EFFECT_NUM_MAX = 32;
namespace OHOS {
namespace Audio {
void EffectControllerReleaseDesc(struct EffectControllerDescriptor *desc)
{
    if (desc == nullptr) {
        return;
    }

    OsalMemFree(desc->effectId);
    desc->effectId = nullptr;

    OsalMemFree(desc->effectName);
    desc->effectName = nullptr;

    OsalMemFree(desc->libName);
    desc->libName = nullptr;

    OsalMemFree(desc->supplier);
    desc->supplier = nullptr;
}

void EffectControllerReleaseDescs(struct EffectControllerDescriptor *descs, const uint32_t *descsLen)
{
    if (descs == nullptr || descsLen == nullptr || *descsLen == 0 || *descsLen > HDF_EFFECT_NUM_MAX) {
        return;
    }

    for (uint32_t i = 0; i < *descsLen; i++) {
        EffectControllerReleaseDesc(&descs[i]);
    }
}

}
}