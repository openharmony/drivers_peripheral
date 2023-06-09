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

#include "huks_hdi_fuzz_common.h"

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