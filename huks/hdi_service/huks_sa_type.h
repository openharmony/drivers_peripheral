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

/**
 * @brief TAG type masks, should be same with huks sa
 */
#define HKS_TAG_TYPE_INVALID  (0U << 28)
#define HKS_TAG_TYPE_INT      (1U << 28)
#define HKS_TAG_TYPE_UINT     (2U << 28)
#define HKS_TAG_TYPE_ULONG    (3U << 28)
#define HKS_TAG_TYPE_BOOL     (4U << 28)
#define HKS_TAG_TYPE_BYTES    (5U << 28)
#define HKS_TAG_TYPE_MASK     (0xF << 28)

/**
 * @brief HksTag enum, partial tags needed by HDI test
 */
enum HksTag {
    HKS_TAG_ALGORITHM            = HKS_TAG_TYPE_UINT | 1,
    HKS_TAG_PURPOSE              = HKS_TAG_TYPE_UINT | 2,
    HKS_TAG_KEY_SIZE             = HKS_TAG_TYPE_UINT | 3,
    HKS_TAG_DIGEST               = HKS_TAG_TYPE_UINT | 4,
    HKS_TAG_PADDING              = HKS_TAG_TYPE_UINT | 5,
    HKS_TAG_BLOCK_MODE           = HKS_TAG_TYPE_UINT | 6,
    HKS_TAG_ASSOCIATED_DATA      = HKS_TAG_TYPE_BYTES | 8,
    HKS_TAG_NONCE                = HKS_TAG_TYPE_BYTES | 9,
    HKS_TAG_KEY_STORAGE_FLAG     = HKS_TAG_TYPE_UINT | 1002,
    HKS_TAG_AUTH_STORAGE_LEVEL   = HKS_TAG_TYPE_UINT | 316,
    HKS_TAG_PROCESS_NAME         = HKS_TAG_TYPE_BYTES | 10001,
};

/**
 * @brief Enum values needed by HDI test, should be same with huks sa
 */
enum HksKeyAlg {
    HKS_ALG_AES = 20,
};

enum HksKeyPurpose {
    HKS_KEY_PURPOSE_ENCRYPT = 1,
    HKS_KEY_PURPOSE_DECRYPT = 2,
};

enum HksKeySize {
    HKS_AES_KEY_SIZE_128 = 128,
};

enum HksKeyPadding {
    HKS_PADDING_NONE = 0,
};

enum HksCipherMode {
    HKS_MODE_GCM = 32,
};

enum HksKeyDigest {
    HKS_DIGEST_NONE = 0,
};

enum HksKeyStorageType {
    HKS_STORAGE_TEMP = 0,
};

enum HksAuthStorageLevel {
    HKS_AUTH_STORAGE_LEVEL_DE = 0,
};

#endif