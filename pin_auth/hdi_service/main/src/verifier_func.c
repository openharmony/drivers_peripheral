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

#include "verifier_func.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "attribute.h"
#include "buffer.h"
#include "pin_db.h"

typedef enum VerifierState {
    VERIFIER_STATE_INIT = 0,
    VERIFIER_STATE_WAIT_SYNC = 1,
    VERIFIER_STATE_WAIT_ACK = 2,
    VERIFIER_STATE_FINISH = 3,
} VerifierState;

typedef struct VerifierSchedule {
    uint64_t scheduleId;
    uint64_t templateId;
    uint64_t timeStamp;
    Buffer *selfUdid;
    Buffer *peerUdid;
    Buffer *peerPubKey;
    Buffer *salt;
    VerifierState state;
} VerifierSchedule;

static KeyPair *g_keyPair = NULL;
static Buffer *g_fwkPubKey = NULL;
static VerifierSchedule *g_verifierSchedule = NULL;

/* This is for example only, Should be implemented in trusted environment. */
ResultCode GenerateVerifierKeyPair(void)
{
    DestroyKeyPair(g_keyPair);
    g_keyPair = GenerateEd25519KeyPair();
    if (g_keyPair == NULL) {
        LOG_ERROR("GenerateVerifierKeyPair fail!");
        return RESULT_GENERAL_ERROR;
    }
    LOG_INFO("GenerateVerifierKeyPair success");
    return RESULT_SUCCESS;
}

void DestroyVerifierKeyPair(void)
{
    LOG_INFO("DestroyVerifierKeyPair");
    DestroyKeyPair(g_keyPair);
    g_keyPair = NULL;
}

/* This is for example only, Should be implemented in trusted environment. */
ResultCode DoGetVerifierExecutorInfo(PinExecutorInfo *pinExecutorInfo)
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

int32_t DoSetVerifierFwkParam(const uint8_t *fwkPubKey, uint32_t fwkPubKeySize)
{
    if ((fwkPubKey == NULL) || (fwkPubKeySize != ED25519_FIX_PUBKEY_BUFFER_SIZE)) {
        LOG_ERROR("DoSetVerifierFwkParam check param fail!");
        return RESULT_BAD_PARAM;
    }
    DestroyBuffer(g_fwkPubKey);
    g_fwkPubKey = CreateBufferByData(fwkPubKey, fwkPubKeySize);
    if (g_fwkPubKey == NULL) {
        LOG_ERROR("DoSetVerifierFwkParam create fwkPubKey fail!");
        return RESULT_NO_MEMORY;
    }
    return RESULT_SUCCESS;
}

static void DestroyVerifierSchedule(void)
{
    if (g_verifierSchedule == NULL) {
        return;
    }
    DestroyBuffer(g_verifierSchedule->selfUdid);
    DestroyBuffer(g_verifierSchedule->peerUdid);
    DestroyBuffer(g_verifierSchedule->peerPubKey);
    DestroyBuffer(g_verifierSchedule->salt);
    Free(g_verifierSchedule);
    g_verifierSchedule= NULL;
}

static bool InitVerifierSchedule(uint64_t scheduleId)
{
    g_verifierSchedule = Malloc(sizeof(VerifierSchedule));
    if (g_verifierSchedule == NULL) {
        LOG_ERROR("malloc VerifierSchedule fail!");
        return false;
    }
    (void)memset_s(g_verifierSchedule, sizeof(VerifierSchedule), 0, sizeof(VerifierSchedule));
    g_verifierSchedule->scheduleId = scheduleId;
    return true;
}

static int32_t GetAuthInfoFromSchedule(uint64_t scheduleId, const uint8_t *extraInfo, uint32_t extraInfoSize)
{
    Attribute *attribute = NULL;
    int32_t result = VerifyAndGetDataAttribute(scheduleId, &attribute, g_fwkPubKey, extraInfo, extraInfoSize);
    IF_TRUE_LOGE_AND_RETURN_VAL(result != RESULT_SUCCESS, result);
    
    result = RESULT_GENERAL_ERROR;
    g_verifierSchedule->selfUdid = GetBufferFromAttribute(attribute, ATTR_LOCAL_UDID, CONST_FWK_UDID_SIZE);
    if (g_verifierSchedule->selfUdid == NULL) {
        LOG_ERROR("get self udid fail!");
        goto EXIT;
    }
    g_verifierSchedule->peerUdid = GetBufferFromAttribute(attribute, ATTR_PEER_UDID, CONST_FWK_UDID_SIZE);
    if (g_verifierSchedule->peerUdid == NULL) {
        LOG_ERROR("get peer udid fail!");
        goto EXIT;
    }
    g_verifierSchedule->peerPubKey = GetBufferFromAttribute(
        attribute, ATTR_PUBLIC_KEY, ED25519_FIX_PUBKEY_BUFFER_SIZE);
    if (g_verifierSchedule->peerPubKey == NULL) {
        LOG_ERROR("get peer public key fail!");
        goto EXIT;
    }
    result = RESULT_SUCCESS;

EXIT:
    FreeAttribute(&attribute);
    return result;
}

static bool SetVerifyAckDataSalt(Attribute *attribute)
{
    if (g_verifierSchedule->salt != NULL) {
        LOG_ERROR("get non null salt!");
        return false;
    }
    g_verifierSchedule->salt = CreateBufferBySize(CONST_KEK_SALT_SIZE);
    if (g_verifierSchedule->salt == NULL) {
        LOG_ERROR("create salt fail!");
        return false;
    }
    int32_t result = SecureRandom(g_verifierSchedule->salt->buf, g_verifierSchedule->salt->maxSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("random salt fail!");
        return false;
    }
    g_verifierSchedule->salt->contentSize = g_verifierSchedule->salt->maxSize;
    if (SetBufferToAttribute(attribute, PIN_ATTR_KEK_SALT, g_verifierSchedule->salt) != RESULT_SUCCESS) {
        LOG_ERROR("set salt fail!");
        return false;
    }
    return true;
}

static bool SetVerifyAckDataPinParam(Attribute *attribute)
{
    uint64_t subType = 0;
    if (GetSubType(g_verifierSchedule->templateId, &subType) != RESULT_SUCCESS) {
        LOG_ERROR("GetSubType fail!");
        return false;
    }
    if (SetAttributeUint64(attribute, ATTR_PIN_SUB_TYPE, subType) != RESULT_SUCCESS) {
        LOG_ERROR("set sub type fail!");
        return false;
    }

    Buffer *algoParam = CreateBufferBySize(CONST_SALT_LEN);
    if (algoParam == NULL) {
        LOG_ERROR("create algoParam fail!");
        return false;
    }
    algoParam->contentSize = algoParam->maxSize;
    uint32_t algoVersion = 0;
    int32_t result = DoGetAlgoParameter(
        g_verifierSchedule->templateId, algoParam->buf, &(algoParam->contentSize), &algoVersion);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoGetAlgoParameter fail!");
        DestroyBuffer(algoParam);
        return false;
    }
    if (SetBufferToAttribute(attribute, PIN_ATTR_ALGO_PARAM, algoParam) != RESULT_SUCCESS) {
        LOG_ERROR("set algo param fail!");
        DestroyBuffer(algoParam);
        return false;
    }
    DestroyBuffer(algoParam);
    if (SetAttributeUint32(attribute, PIN_ATTR_ALGO_VERSION, algoVersion) != RESULT_SUCCESS) {
        LOG_ERROR("set algo version fail!");
        return false;
    }
    return true;
}

static Attribute *GetVerifyAckData()
{
    Attribute *attribute = GetAttributeDataBase(g_verifierSchedule->scheduleId, REMOTE_PIN_VERIFIER_ACK);
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, NULL);

    if (!SetVerifyAckDataSalt(attribute)) {
        LOG_ERROR("SetVerifyAckDataSalt fail!");
        goto ERROR;
    }

    if (!SetVerifyAckDataPinParam(attribute)) {
        LOG_ERROR("SetVerifyAckDataPinParam fail!");
        goto ERROR;
    }
    
    return attribute;

ERROR:
    FreeAttribute(&attribute);
    return NULL;
}

static int32_t GetResultTlv(VerifierMsg *verifierMsg)
{
    Attribute *attribute = GetAttributeDataBase(g_verifierSchedule->scheduleId, REMOTE_PIN_MSG_NONE);
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, RESULT_GENERAL_ERROR);

    int32_t result = RESULT_GENERAL_ERROR;
    if (!SetResultDataInfo(
        attribute, PinResultToFwkResult(verifierMsg->authResult), g_verifierSchedule->templateId, NULL)) {
        LOG_ERROR("SetResultDataInfo fail");
        goto EXIT;
    }

    result = FormatTlvMsg(attribute, g_keyPair, verifierMsg->msgOut, &(verifierMsg->msgOutSize));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("FormatTlvMsg fail");
        goto EXIT;
    }

EXIT:
    FreeAttribute(&attribute);
    return result;
}

static bool IsVeriferMsgValid(VerifierMsg *verifierMsg)
{
    if (verifierMsg == NULL) {
        LOG_ERROR("verifierMsg is null");
        return false;
    }
    if ((verifierMsg->msgIn == NULL) || (verifierMsg->msgInSize == 0)) {
        LOG_ERROR("verifierMsg msgIn is invalid");
        return false;
    }
    if ((verifierMsg->msgOut == NULL) || (verifierMsg->msgOutSize == 0)) {
        LOG_ERROR("verifierMsg msgOut is invalid");
        return false;
    }
    return true;
}

int32_t DoVerifierAuth(uint64_t scheduleId, uint64_t templateId, VerifierMsg *verifierMsg)
{
    LOG_INFO("DoVerifierAuth start %{public}x", (uint16_t)scheduleId);
    if (!IsVeriferMsgValid(verifierMsg)) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }
    DestroyVerifierSchedule();
    if (!InitVerifierSchedule(scheduleId)) {
        LOG_ERROR("InitVerifierSchedule fail!");
        return RESULT_GENERAL_ERROR;
    }
    int32_t result = GetAuthInfoFromSchedule(scheduleId, verifierMsg->msgIn, verifierMsg->msgInSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAuthInfoFromSchedule fail!");
        goto ERROR;
    }
    g_verifierSchedule->templateId = templateId;
    g_verifierSchedule->state = VERIFIER_STATE_WAIT_SYNC;

    PinCredentialInfos pinCredentialInfo;
    result = DoQueryPinInfo(templateId, &pinCredentialInfo);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoQueryPinInfo fail!");
        goto ERROR;
    }
    if (pinCredentialInfo.freezeTime == 0) {
        LOG_INFO("DoVerifierAuth success");
        verifierMsg->authResult = RESULT_SUCCESS;
        verifierMsg->msgOutSize = 0;
        return RESULT_SUCCESS;
    }

    LOG_ERROR("DoVerifierAuth locked");
    verifierMsg->authResult = RESULT_PIN_FREEZE;
    result = GetResultTlv(verifierMsg);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetResultTlv fail!");
        goto ERROR;
    }
    return RESULT_SUCCESS;

ERROR:
    DestroyVerifierSchedule();
    return result;
}

int32_t DoCancelVerifierAuth()
{
    LOG_INFO("DoCancelVerifierAuth start");
    DestroyVerifierSchedule();
    return RESULT_SUCCESS;
}

static bool CheckCurrentSchedule(uint64_t scheduleId)
{
    if (g_verifierSchedule == NULL) {
        LOG_ERROR("schedule not exist");
        return false;
    }
    if (g_verifierSchedule->scheduleId != scheduleId) {
        LOG_ERROR("schedule:%{public}x not match current:%{public}x",
            (uint16_t)scheduleId, (uint16_t)(g_verifierSchedule->scheduleId));
        return false;
    }
    return true;
}

static int32_t DoHandleCollectorSync(VerifierMsg *verifierMsg)
{
    verifierMsg->isAuthEnd = false;
    Attribute *dataIn = NULL;
    int32_t result = VerifyAndGetDataAttribute(g_verifierSchedule->scheduleId,
        &dataIn, g_verifierSchedule->peerPubKey, verifierMsg->msgIn, verifierMsg->msgInSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("VerifyAndGetDataAttribute fail");
        return result;
    }

    result = CheckAttributeDataBase(
        dataIn, g_verifierSchedule->scheduleId, REMOTE_PIN_COLLECTOR_SYNC, &(g_verifierSchedule->timeStamp));
    FreeAttribute(&dataIn);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("CheckAttributeDataBase fail");
        return result;
    }

    Attribute *dataOut = GetVerifyAckData();
    if (dataOut == NULL) {
        LOG_ERROR("GetVerifyAckData fail!");
        return RESULT_GENERAL_ERROR;
    }
    result = FormatTlvMsg(dataOut, g_keyPair, verifierMsg->msgOut, &(verifierMsg->msgOutSize));
    FreeAttribute(&dataOut);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("FormatTlvMsg fail!");
        return result;
    }
    g_verifierSchedule->state = VERIFIER_STATE_WAIT_ACK;
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

static bool GetAesGcmParam(AesGcmParam *aesGcmParam, const Attribute *attribute)
{
    (void)memset_s(aesGcmParam, sizeof(AesGcmParam), 0, sizeof(AesGcmParam));
    aesGcmParam->aad = CreateBufferByData((const uint8_t *)CONST_KEK_AAD, CONST_KEK_AAD_SIZE);
    if (aesGcmParam->aad == NULL) {
        LOG_ERROR("create aad buffer fail");
        goto ERROR;
    }
    aesGcmParam->iv = GetBufferFromAttribute(attribute, PIN_ATTR_KEK_IV, AES_GCM_256_IV_SIZE);
    if (aesGcmParam->iv == NULL) {
        LOG_ERROR("create iv buffer fail");
        goto ERROR;
    }
    if (GetDistributeKey(g_verifierSchedule->peerUdid, g_verifierSchedule->salt, &(aesGcmParam->key)) !=
        RESULT_SUCCESS) {
        LOG_ERROR("GetDistributeKey fail");
        goto ERROR;
    }
    return true;

ERROR:
    DestroyAesGcmParam(aesGcmParam);
    return false;
}

static Buffer *GetPinData(const Attribute *attribute)
{
    AesGcmParam aesGcmParam = {};
    if (!GetAesGcmParam(&aesGcmParam, attribute)) {
        LOG_ERROR("GetAesGcmParam fail");
        return NULL;
    }
    int32_t result = RESULT_GENERAL_ERROR;
    Buffer *plainText = NULL;
    Buffer *tag = NULL;
    Buffer *cipherText = GetBufferFromAttribute(attribute, PIN_ATTR_KEK_SECRET, CONST_PIN_DATA_LEN);
    if (cipherText == NULL) {
        LOG_ERROR("GetBufferFromAttribute secret fail");
        goto EXIT;
    }
    tag = GetBufferFromAttribute(attribute, PIN_ATTR_KEK_TAG, AES_GCM_256_TAG_SIZE);
    if (tag == NULL) {
        LOG_ERROR("GetBufferFromAttribute tag fail");
        goto EXIT;
    }
    result = AesGcm256Decrypt(cipherText, &aesGcmParam, tag, &plainText);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("AesGcm256Decrypt fail");
        goto EXIT;
    }

EXIT:
    DestroyAesGcmParam(&aesGcmParam);
    DestroyBuffer(cipherText);
    DestroyBuffer(tag);
    return plainText;
}

static int32_t AuthPin(VerifierMsg *verifierMsg, Buffer *pinDataBuf)
{
    LOG_INFO("start");
    verifierMsg->isAuthEnd = true;
    verifierMsg->authResult = RESULT_GENERAL_ERROR;

    PinCredentialInfos pinCredentialInfo = {};
    ResultCode ret = DoQueryPinInfo(g_verifierSchedule->templateId, &pinCredentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("DoQueryPinInfo fail.");
        verifierMsg->msgOutSize = 0;
        return RESULT_SUCCESS;
    }

    if (pinCredentialInfo.freezeTime == 0) {
        ResultCode compareRet = RESULT_COMPARE_FAIL;
        ResultCode result = AuthPinById(pinDataBuf, g_verifierSchedule->templateId, 0, NULL, &compareRet);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("AuthPinById fail!");
        }
        verifierMsg->authResult = result != RESULT_SUCCESS ? result : compareRet;
    } else {
        LOG_ERROR("Pin is freezing.");
        verifierMsg->authResult = RESULT_PIN_FREEZE;
    }

    ret = GetResultTlv(verifierMsg);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetResultTlv fail!");
        verifierMsg->msgOutSize = 0;
    }
    return RESULT_SUCCESS;
}

static int32_t DoHandleCollectorAck(VerifierMsg *verifierMsg)
{
    Attribute *dataIn = NULL;
    int32_t result = VerifyAndGetDataAttribute(g_verifierSchedule->scheduleId,
        &dataIn, g_verifierSchedule->peerPubKey, verifierMsg->msgIn, verifierMsg->msgInSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("VerifyAndGetDataAttribute fail");
        return result;
    }

    result = CheckAttributeDataBase(
        dataIn, g_verifierSchedule->scheduleId, REMOTE_PIN_COLLECTOR_ACK, &(g_verifierSchedule->timeStamp));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("CheckAttributeDataBase fail");
        FreeAttribute(&dataIn);
        return result;
    }

    Buffer *pinData = GetPinData(dataIn);
    FreeAttribute(&dataIn);
    if (pinData == NULL) {
        LOG_ERROR("GetPinData fail");
        return RESULT_GENERAL_ERROR;
    }

    result = AuthPin(verifierMsg, pinData);
    DestroyBuffer(pinData);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("AuthPin fail");
    }
    DestroyVerifierSchedule();
    return result;
}

int32_t DoSendMessageToVerifier(uint64_t scheduleId, VerifierMsg *verifierMsg)
{
    LOG_INFO("DoSendMessageToVerifier start schedule:%{public}x", (uint16_t)scheduleId);
    if (!CheckCurrentSchedule(scheduleId) || !IsVeriferMsgValid(verifierMsg)) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }
    LOG_INFO("DoSendMessageToVerifier current state:%{public}d", g_verifierSchedule->state);
    if (g_verifierSchedule->state == VERIFIER_STATE_WAIT_SYNC) {
        return DoHandleCollectorSync(verifierMsg);
    }
    if (g_verifierSchedule->state == VERIFIER_STATE_WAIT_ACK) {
        return DoHandleCollectorAck(verifierMsg);
    }
    return RESULT_GENERAL_ERROR;
}
