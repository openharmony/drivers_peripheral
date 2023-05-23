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

#ifndef IHUKSTYPES_H
#define IHUKSTYPES_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct HuksBlob {
    uint8_t* data;
    uint32_t dataLen;
};

struct HuksParamSet {
    uint8_t* data;
    uint32_t dataLen;
};

enum HuksChipsetPlatformDecryptScene {
    HUKS_CHIPSET_PLATFORM_DECRYPT_SCENCE_TA_TO_TA = 1,
};
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // IHUKSTYPES_H