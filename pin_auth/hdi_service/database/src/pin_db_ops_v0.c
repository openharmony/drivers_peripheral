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

#include "pin_db_ops_v0.h"

#include <inttypes.h>
#include "securec.h"

#include "adaptor_file.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "adaptor_time.h"
#include "file_operator.h"

#include "pin_db_ops_base.h"

void GetMaxLockedAntiBruteInfo(AntiBruteInfoV0 *antiBruteInfoV0)
{
    if (antiBruteInfoV0 == NULL) {
        return;
    }
    antiBruteInfoV0->authErrorCount = ATTI_BRUTE_SECOND_STAGE;
    antiBruteInfoV0->startFreezeTime = GetRtcTime();
}

static ResultCode GetPinIndexV0(uint8_t *data, uint32_t dataLen, PinDbV0 *pinDbV0)
{
    if (sizeof(PinInfoV0) * pinDbV0->pinIndexLen != dataLen) {
        LOG_ERROR("bad data length.");
        return RESULT_GENERAL_ERROR;
    }
    pinDbV0->pinIndex = (PinIndexV0 *)Malloc(sizeof(PinIndexV0) * pinDbV0->pinIndexLen);
    if (pinDbV0->pinIndex == NULL) {
        LOG_ERROR("pinIndex malloc fail.");
        return RESULT_NO_MEMORY;
    }
    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    for (uint32_t i = 0; i < pinDbV0->pinIndexLen; i++) {
        if (GetDataFromBuf(&temp, &tempLen, (uint8_t *)(&(pinDbV0->pinIndex[i].pinInfo)),
            sizeof(pinDbV0->pinIndex[i].pinInfo)) != RESULT_SUCCESS) {
            LOG_ERROR("read pinInfo fail.");
            Free(pinDbV0->pinIndex);
            pinDbV0->pinIndex = NULL;
            return RESULT_BAD_READ;
        }
        if (ReadPinFile((uint8_t *)(&(pinDbV0->pinIndex[i].antiBruteInfo)),
            sizeof(pinDbV0->pinIndex[i].antiBruteInfo),
            pinDbV0->pinIndex[i].pinInfo.templateId, ANTI_BRUTE_SUFFIX) != RESULT_SUCCESS) {
            LOG_ERROR("read AntiBruteInfo fail.");
            GetMaxLockedAntiBruteInfo(&(pinDbV0->pinIndex[i].antiBruteInfo));
            (void)WritePinFile((uint8_t *)(&(pinDbV0->pinIndex[i].antiBruteInfo)),
                sizeof(pinDbV0->pinIndex[i].antiBruteInfo),
                pinDbV0->pinIndex[i].pinInfo.templateId, ANTI_BRUTE_SUFFIX);
        }
    }
    return RESULT_SUCCESS;
}

static bool UnpackPinDbV0(uint8_t *data, uint32_t dataLen, PinDbV0 *pinDbV0)
{
    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    if (GetDataFromBuf(&temp, &tempLen, (uint8_t *)(&(pinDbV0->version)),
        sizeof(pinDbV0->version)) != RESULT_SUCCESS) {
        LOG_ERROR("read version fail.");
        return false;
    }
    if (pinDbV0->version != DB_VERSION_0) {
        LOG_ERROR("read version %{public}u.", pinDbV0->version);
        return false;
    }
    if (GetDataFromBuf(&temp, &tempLen, (uint8_t *)(&(pinDbV0->pinIndexLen)),
        sizeof(pinDbV0->pinIndexLen)) != RESULT_SUCCESS) {
        LOG_ERROR("read pinIndexLen fail.");
        return false;
    }
    if (pinDbV0->pinIndexLen > MAX_CRYPTO_INFO_SIZE) {
        pinDbV0->pinIndexLen = 0;
        LOG_ERROR("pinIndexLen too large.");
        return false;
    }
    if (pinDbV0->pinIndexLen == 0) {
        pinDbV0->pinIndex = NULL;
        return true;
    }
    if (GetPinIndexV0(temp, tempLen, pinDbV0) != RESULT_SUCCESS) {
        pinDbV0->pinIndexLen = 0;
        LOG_ERROR("GetPinIndexV0 fail.");
        return false;
    }
    return true;
}

void *GetPinDbV0(uint8_t *data, uint32_t dataLen)
{
    if (data == NULL || dataLen == 0) {
        LOG_INFO("no data provided");
        return NULL;
    }
    PinDbV0 *pinDbV0 = Malloc(sizeof(PinDbV0));
    if (pinDbV0 == NULL) {
        LOG_ERROR("get pinDbV0 fail");
        return NULL;
    }
    (void)memset_s(pinDbV0, sizeof(PinDbV0), 0, sizeof(PinDbV0));
    if (!UnpackPinDbV0(data, dataLen, pinDbV0)) {
        LOG_ERROR("UnpackPinDbV0 fail");
        FreePinDbV0((void **)(&pinDbV0));
        return NULL;
    }
    return pinDbV0;
}

void FreePinDbV0(void **pinDb)
{
    if (pinDb == NULL) {
        return;
    }
    PinDbV0 *pinDbV0 = *pinDb;
    if (pinDbV0 == NULL) {
        return;
    }
    if (pinDbV0->pinIndex != NULL) {
        Free(pinDbV0->pinIndex);
    }
    Free(*pinDb);
    *pinDb = NULL;
}
