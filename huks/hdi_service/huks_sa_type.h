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

#ifndef HUKS_SA_TYPE_H
#define HUKS_SA_TYPE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * @brief HksBlob should be same with huks sa
 */
struct HksBlob {
    uint32_t size;
    uint8_t *data;
};

/**
 * @brief HksParam should be same with huks sa
 */
struct HksParam {
    uint32_t tag;
    union {
        bool boolParam;
        int32_t int32Param;
        uint32_t uint32Param;
        uint64_t uint64Param;
        struct HksBlob blob;
    };
};

/**
 * @brief HksParamSet set should be same with huks sa
 */
struct HksParamSet {
    uint32_t paramSetSize;
    uint32_t paramsCnt;
    struct HksParam params[];
};

/**
 * @brief hks chipset platform decrypt scene should be same with huks sa
 */
enum HksChipsetPlatformDecryptScene {
    HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA = 1,
};


/**
 * @brief huks hdi error code should be same with huks sa
 */
enum HuksErrorCode {
    HUKS_SUCCESS = 0,
    HUKS_FAILURE = -1,
    HUKS_ERROR_NULL_POINTER = -14,
    HUKS_ERROR_MALLOC_FAIL = -21,
    HUKS_ERROR_API_NOT_SUPPORTED = -45,
};

#endif