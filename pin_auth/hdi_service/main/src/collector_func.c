/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "collector_func.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "attribute.h"
#include "buffer.h"

typedef enum CollectorState {
    COLLECTOR_STATE_INIT = 0,
    COLLECTOR_STATE_WAIT_ACK = 1,
    COLLECTOR_STATE_WAIT_PIN = 2,
    COLLECTOR_STATE_FINISH = 3,
} CollectorState;

typedef struct CollectorSchedule {
    uint64_t scheduleId;
    uint64_t timeStamp;
    Buffer *selfUdid;
    Buffer *peerUdid;
    Buffer *peerPubKey;
    Buffer *challenge;
    Buffer *salt;
    CollectorState state;
} CollectorSchedule;

static KeyPair *g_keyPair = NULL;
static Buffer *g_fwkPubKey = NULL;
static CollectorSchedule *g_collectorSchedule = NULL;

/* This is for example only, Should be implemented in trusted environment. */
int32_t GenerateCollectorKeyPair(void)
{
    DestroyKeyPair(g_keyPair);
    g_keyPair = GenerateEd25519KeyPair();
    if (g_keyPair == NULL) {
        LOG_ERROR("GenerateCollectorKeyPair fail");
        return RESULT_GENERAL_ERROR;
    }
    LOG_INFO("GenerateCollectorKeyPair success");
    return RESULT_SUCCESS;
}

void DestroyCollectorKeyPair(void)
{
    LOG_INFO("DestroyCollectorKeyPair");
    DestroyKeyPair(g_keyPair);
    g_keyPair = NULL;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t DoGetCollectorExecutorInfo(PinExecutorInfo *pinExecutorInfo)
{
    if (pinExecutorInfo == NULL) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }
    if (!IsEd25519KeyPairValid(g_keyPair)) {
        LOG_ERROR("key pair not init!");
        return RESULT_NEED_INIT;
    }
    uint32_t pubKeyLen = ED25519_FIX_PUBKEY_BUFFER_SIZE;
    if (GetBufferData(g_keyPair->pubKey, pinExecutorInfo->pubKey, &pubKeyLen) != RESULT_SUCCESS) {
        LOG_ERROR("GetBufferData fail!");
        return RESULT_UNKNOWN;
    }
    pinExecutorInfo->esl = PIN_EXECUTOR_SECURITY_LEVEL;
    pinExecutorInfo->maxTemplateAcl = PIN_CAPABILITY_LEVEL;
    return RESULT_SUCCESS;
}

int32_t DoSetCollectorFwkParam(const uint8_t *fwkPubKey, uint32_t fwkPubKeySize)
{
    if ((fwkPubKey == NULL) || (fwkPubKeySize != ED25519_FIX_PUBKEY_BUFFER_SIZE)) {
        LOG_ERROR("DoSetCollectorFwkParam check param fail!");
        return RESULT_BAD_PARAM;
    }
    DestroyBuffer(g_fwkPubKey);
    g_fwkPubKey = CreateBufferByData(fwkPubKey, fwkPubKeySize);
    if (g_fwkPubKey == NULL) {
        LOG_ERROR("DoSetCollectorFwkParam create fwkPubKey fail!");
        return RESULT_NO_MEMORY;
    }
    return RESULT_SUCCESS;
}

static void DestroyCollectorSchedule(void)
{
    if (g_collectorSchedule == NULL) {
        return;
    }
    DestroyBuffer(g_collectorSchedule->selfUdid);
    DestroyBuffer(g_collectorSchedule->peerUdid);
    DestroyBuffer(g_collectorSchedule->peerPubKey);
    DestroyBuffer(g_collectorSchedule->challenge);
    DestroyBuffer(g_collectorSchedule->salt);
    Free(g_collectorSchedule);
    g_collectorSchedule= NULL;
}

static int32_t GetCollectInfoFromSchedule(uint64_t scheduleId, const uint8_t *extraInfo, uint32_t extraInfoSize)
{
    Attribute *attribute = NULL;
    int32_t result = VerifyAndGetDataAttribute(scheduleId, &attribute, g_fwkPubKey, extraInfo, extraInfoSize);
    IF_TRUE_LOGE_AND_RETURN_VAL(result != RESULT_SUCCESS, result);

    result = RESULT_GENERAL_ERROR;
    g_collectorSchedule->selfUdid = GetBufferFromAttribute(attribute, ATTR_LOCAL_UDID, CONST_FWK_UDID_SIZE);
    if (g_collectorSchedule->selfUdid == NULL) {
        LOG_ERROR("get self udid fail!");
        goto EXIT;
    }
    g_collectorSchedule->peerUdid = GetBufferFromAttribute(attribute, ATTR_PEER_UDID, CONST_FWK_UDID_SIZE);
    if (g_collectorSchedule->peerUdid == NULL) {
        LOG_ERROR("get peer udid fail!");
        goto EXIT;
    }
    g_collectorSchedule->peerPubKey = GetBufferFromAttribute(
        attribute, ATTR_PUBLIC_KEY, ED25519_FIX_PUBKEY_BUFFER_SIZE);
    if (g_collectorSchedule->peerPubKey == NULL) {
        LOG_ERROR("get peer public key fail!");
        goto EXIT;
    }
    g_collectorSchedule->challenge = GetBufferFromAttribute(attribute, ATTR_CHALLENGE, CONST_CHALLENGE_LEN);
    if (g_collectorSchedule->challenge == NULL) {
        LOG_ERROR("get challenge fail!");
        goto EXIT;
    }

    result = RESULT_SUCCESS;

EXIT:
    FreeAttribute(&attribute);
    return result;
}

static bool InitCollectorSchedule(uint64_t scheduleId)
{
    g_collectorSchedule = Malloc(sizeof(CollectorSchedule));
    if (g_collectorSchedule == NULL) {
        LOG_ERROR("malloc CollectorSchedule fail!");
        return false;
    }
    (void)memset_s(g_collectorSchedule, sizeof(CollectorSchedule), 0, sizeof(CollectorSchedule));
    g_collectorSchedule->scheduleId = scheduleId;
    return true;
}

int32_t DoCollect(
    uint64_t scheduleId, const uint8_t *extraInfo, uint32_t extraInfoSize, uint8_t *msg, uint32_t *msgSize)
{
    LOG_INFO("DoCollect start %{public}x", (uint16_t)scheduleId);
    if ((extraInfo == NULL) || (extraInfoSize == 0) || (extraInfoSize > MAX_EXECUTOR_MSG_LEN) ||
        (msg == NULL) || (msgSize == NULL) || ((*msgSize) == 0)) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }
    DestroyCollectorSchedule();
    if (!InitCollectorSchedule(scheduleId)) {
        LOG_ERROR("InitCollectorSchedule fail!");
        return RESULT_GENERAL_ERROR;
    }
    
    int32_t result = GetCollectInfoFromSchedule(scheduleId, extraInfo, extraInfoSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetCollectInfoFromSchedule fail!");
        goto ERROR;
    }

    Attribute *attribute = GetAttributeDataBase(g_collectorSchedule->scheduleId, REMOTE_PIN_COLLECTOR_SYNC);
    if (attribute == NULL) {
        LOG_ERROR("GetAttributeDataBase fail!");
        result = RESULT_GENERAL_ERROR;
        goto ERROR;
    }

    result = FormatTlvMsg(attribute, g_keyPair, msg, msgSize);
    FreeAttribute(&attribute);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("FormatTlvMsg fail!");
        goto ERROR;
    }
    g_collectorSchedule->state = COLLECTOR_STATE_WAIT_ACK;
    return RESULT_SUCCESS;

ERROR:
    DestroyCollectorSchedule();
    return result;
}

int32_t DoCancelCollect()
{
    LOG_INFO("DoCancelCollect start");
    DestroyCollectorSchedule();
    return RESULT_SUCCESS;
}

static bool CheckCurrentSchedule(uint64_t scheduleId, CollectorState state)
{
    if (g_collectorSchedule == NULL) {
        LOG_ERROR("schedule not exist");
        return false;
    }
    if (g_collectorSchedule->scheduleId != scheduleId) {
        LOG_ERROR("schedule:%{public}x not match current:%{public}x",
            (uint16_t)scheduleId, (uint16_t)(g_collectorSchedule->scheduleId));
        return false;
    }
    if (g_collectorSchedule->state != state) {
        LOG_ERROR("state:%{public}d not match current:%{public}d", state, g_collectorSchedule->state);
        return false;
    }
    return true;
}

static int32_t GetAlgoParam(const Attribute *data, AlgoParamOut *algoParam)
{
    int32_t result = GetAttributeUint64(data, ATTR_PIN_SUB_TYPE, &(algoParam->subType));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("get sub type fail");
        return result;
    }
    result = GetAttributeUint32(data, PIN_ATTR_ALGO_VERSION, &(algoParam->algoVersion));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("get algo version fail");
        return result;
    }
    Uint8Array uint8Array = {
        .data = algoParam->algoParameter,
        .len = sizeof(algoParam->algoParameter),
    };
    result = GetAttributeUint8Array(data, PIN_ATTR_ALGO_PARAM, &uint8Array);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("get algo param fail");
        return result;
    }
    if (uint8Array.len != sizeof(algoParam->algoParameter)) {
        LOG_ERROR("get algo param fail");
        return RESULT_GENERAL_ERROR;
    }
    if (memcpy_s(algoParam->challenge, sizeof(algoParam->challenge),
        g_collectorSchedule->challenge->buf, g_collectorSchedule->challenge->contentSize) != EOK) {
        LOG_ERROR("copy challenge fail");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

int32_t DoSendMessageToCollector(uint64_t scheduleId, const uint8_t *msg, uint32_t msgSize, AlgoParamOut *algoParam)
{
    LOG_INFO("SendMessageToCollector start schedule:%{public}x", (uint16_t)scheduleId);
    if (!CheckCurrentSchedule(scheduleId, COLLECTOR_STATE_WAIT_ACK) ||
        (msg == NULL) || (msgSize == 0) || (algoParam == NULL)) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }
    Attribute *data = NULL;
    int32_t result = VerifyAndGetDataAttribute(scheduleId, &data, g_collectorSchedule->peerPubKey, msg, msgSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("VerifyAndGetDataAttribute fail");
        return result;
    }

    result = CheckAttributeDataBase(
        data, g_collectorSchedule->scheduleId, REMOTE_PIN_VERIFIER_ACK, &(g_collectorSchedule->timeStamp));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("CheckAttributeDataBase fail");
        goto EXIT;
    }

    g_collectorSchedule->salt = GetBufferFromAttribute(data, PIN_ATTR_KEK_SALT, CONST_KEK_SALT_SIZE);
    if (g_collectorSchedule->salt == NULL) {
        LOG_ERROR("get kek salt fail");
        result = RESULT_GENERAL_ERROR;
        goto EXIT;
    }

    result = GetAlgoParam(data, algoParam);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAlgoParam fail");
        goto EXIT;
    }

    g_collectorSchedule->state = COLLECTOR_STATE_WAIT_PIN;

EXIT:
    FreeAttribute(&data);
    return result;
}

static void DestroyAesGcmParam(AesGcmParam *aesGcmParam)
{
    DestroyBuffer(aesGcmParam->key);
    aesGcmParam->key = NULL;
    DestroyBuffer(aesGcmParam->iv);
    aesGcmParam->iv = NULL;
    DestroyBuffer(aesGcmParam->aad);
    aesGcmParam->aad = NULL;
}

static bool GetAesGcmParam(AesGcmParam *aesGcmParam)
{
    (void)memset_s(aesGcmParam, sizeof(AesGcmParam), 0, sizeof(AesGcmParam));
    aesGcmParam->aad = CreateBufferByData((const uint8_t *)CONST_KEK_AAD, CONST_KEK_AAD_SIZE);
    if (aesGcmParam->aad == NULL) {
        LOG_ERROR("create aad buffer fail");
        goto ERROR;
    }
    aesGcmParam->iv = CreateBufferBySize(AES_GCM_256_IV_SIZE);
    if (aesGcmParam->iv == NULL) {
        LOG_ERROR("create iv buffer fail");
        goto ERROR;
    }
    if (SecureRandom(aesGcmParam->iv->buf, aesGcmParam->iv->maxSize) != RESULT_SUCCESS) {
        LOG_ERROR("SecureRandom iv fail");
        goto ERROR;
    }
    aesGcmParam->iv->contentSize = aesGcmParam->iv->maxSize;
    if (GetDistributeKey(g_collectorSchedule->peerUdid, g_collectorSchedule->salt, &(aesGcmParam->key)) !=
        RESULT_SUCCESS) {
        LOG_ERROR("GetDistributeKey fail");
        goto ERROR;
    }
    return true;

ERROR:
    DestroyAesGcmParam(aesGcmParam);
    return false;
}

static int32_t SetEncryptParam(Attribute *attribute, uint8_t *pinData, uint32_t pinDataSize)
{
    AesGcmParam aesGcmParam = {};
    if (!GetAesGcmParam(&aesGcmParam)) {
        LOG_ERROR("GetAesGcmParam fail");
        return RESULT_GENERAL_ERROR;
    }
    Buffer plainText = GetTmpBuffer(pinData, pinDataSize, pinDataSize);
    Buffer *cipherText = NULL;
    Buffer *tag = NULL;
    int32_t result = AesGcm256Encrypt(&plainText, &aesGcmParam, &cipherText, &tag);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("AesGcm256Encrypt fail");
        goto EXIT;
    }
    result = SetBufferToAttribute(attribute, PIN_ATTR_KEK_IV, aesGcmParam.iv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set attribute iv fail");
        goto EXIT;
    }
    result = SetBufferToAttribute(attribute, PIN_ATTR_KEK_SECRET, cipherText);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set attribute secret fail");
        goto EXIT;
    }
    result = SetBufferToAttribute(attribute, PIN_ATTR_KEK_TAG, tag);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set attribute tag fail");
        goto EXIT;
    }

EXIT:
    DestroyAesGcmParam(&aesGcmParam);
    DestroyBuffer(cipherText);
    DestroyBuffer(tag);
    return result;
}

int32_t DoSetDataToCollector(
    uint64_t scheduleId, uint8_t *pinData, uint32_t pinDataSize, uint8_t *msg, uint32_t *msgSize)
{
    LOG_INFO("DoSetDataToCollector start schedule:%{public}x", (uint16_t)scheduleId);
    int32_t result = RESULT_BAD_PARAM;
    Attribute *attribute = NULL;
    if (!CheckCurrentSchedule(scheduleId, COLLECTOR_STATE_WAIT_PIN) ||
        (pinData == NULL) || (pinDataSize != CONST_PIN_DATA_LEN) || (msg == NULL) || ((*msgSize) == 0)) {
        LOG_ERROR("check param fail!");
        goto EXIT;
    }

    attribute = GetAttributeDataBase(scheduleId, REMOTE_PIN_COLLECTOR_ACK);
    if (attribute == NULL) {
        LOG_ERROR("GetAttributeDataBase fail");
        result = RESULT_GENERAL_ERROR;
        goto EXIT;
    }
    result = SetEncryptParam(attribute, pinData, pinDataSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetEncryptParam fail");
        goto EXIT;
    }
    result = FormatTlvMsg(attribute, g_keyPair, msg, msgSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("FormatTlvMsg fail");
        goto EXIT;
    }

    g_collectorSchedule->state = COLLECTOR_STATE_FINISH;

EXIT:
    if ((pinData != NULL) && (pinDataSize != 0)) {
        (void)memset_s(pinData, pinDataSize, 0, pinDataSize);
    }
    FreeAttribute(&attribute);
    return result;
}
