/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "signature_operation.h"

#include "securec.h"

#include "buffer.h"
#include "adaptor_algorithm.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#undef LOG_TAG
#define LOG_TAG "USER_AUTH_HDI"

namespace OHOS {
namespace HDI {
namespace UserAuth {
namespace {
    KeyPair *g_keyPair = nullptr;
    constexpr uint32_t TAG_AND_LEN_BYTE = 8;
    constexpr uint32_t FACE_AUTH_CAPABILITY_LEVEL = 3;
    constexpr uint32_t RESULT_TLV_LEN = 500;
} // namespace

enum AuthAttributeType : uint32_t {
    /* Root tag */
    ATTR_ROOT = 100000,
    /* Result code */
    ATTR_RESULT_CODE = 100001,
    /* Tag of signature data in TLV */
    ATTR_SIGNATURE = 100004,
    /* Identify mode */
    ATTR_IDENTIFY_MODE = 100005,
    /* Tag of templateId data in TLV */
    ATTR_TEMPLATE_ID = 100006,
    /* Tag of templateId list data in TLV */
    ATTR_TEMPLATE_ID_LIST = 100007,
    /* Expected attribute, tag of remain count in TLV */
    ATTR_REMAIN_ATTEMPTS = 100009,
    /* Remain time */
    ATTR_LOCKOUT_DURATION = 100010,
    /* Session id, required when decode in C */
    ATTR_SCHEDULE_ID = 100014,
    /* Package name */
    ATTR_CALLER_NAME = 100015,
    /* Schedule version */
    AUTH_SCHEDULE_VERSION = 100016,
    /* Tag of lock out template in TLV */
    AUTH_LOCK_OUT_TEMPLATE = 100018,
    /* Tag of data */
    ATTR_DATA = 100020,
    /* Tag of auth subType */
    ATTR_PIN_SUB_TYPE = 100021,
    /* Tag of auth schedule mode */
    ATTR_SCHEDULE_MODE = 100022,
    /* Tag of property */
    ATTR_PROPERTY_MODE = 100023,
    /* Tag of auth type */
    ATTR_TYPE = 100024,
    /* Tag of cred id */
    ATTR_CREDENTIAL_ID = 100025,
    /* Controller */
    ATTR_CONTROLLER = 100026,
    /* calleruid */
    ATTR_CALLER_UID = 100027,
    /* result */
    ATTR_RESULT = 100028,
    /* capability level */
    ATTR_CAPABILITY_LEVEL = 100029,
    /* algorithm setinfo */
    ATTR_ALGORITHM_INFO = 100030,
    /* time stamp */
    ATTR_TIME_STAMP = 100031,
    /* root secret */
    ATTR_ROOT_SECRET = 100032,
    /* attrs */
    ATTR_ATTRS = 100033,
    /* executor index */
    ATTR_EXECUTOR_INDEX = 100034,
    /* public key */
    ATTR_PUBLIC_KEY = 100035,
    /* executor matcher */
    ATTR_EXECUTOR_MATCHER = 100036,
    /* local udid */
    ATTR_LOCAL_UDID = 100037,
    /* peer udid */
    ATTR_PEER_UDID = 100038,
    /* user id */
    ATTR_USER_ID = 100041,
    /* token */
    ATTR_TOKEN = 100042,
    /* executor role */
    ATTR_EXECUTOR_ROLE = 100043,
    /* esl */
    ATTR_ESL = 100044,
    /* VERIFIER udid */
    ATTR_VERIFIER_UDID = 100045,
    /* COLLECTOR udid */
    ATTR_COLLECTOR_UDID = 100046,
    /* Challenge */
    ATTR_CHALLENGE = 100066,
};

ResultCode GenerateExecutorKeyPair()
{
    g_keyPair = GenerateEd25519KeyPair();
    if (g_keyPair == nullptr) {
        IAM_LOGE("GenerateEd25519Keypair fail");
        return RESULT_GENERAL_ERROR;
    }
    IAM_LOGI("GenerateExecutorKeyPair success");
    return RESULT_SUCCESS;
}

static ResultCode WriteTlvHead(const AuthAttributeType type, const uint32_t length, Buffer *buf)
{
    int32_t tempType = type;
    if (memcpy_s(buf->buf + buf->contentSize, buf->maxSize - buf->contentSize, &tempType, sizeof(tempType)) != EOK) {
        IAM_LOGE("copy type fail");
        return RESULT_GENERAL_ERROR;
    }
    buf->contentSize += sizeof(tempType);
    if (memcpy_s(buf->buf + buf->contentSize, buf->maxSize - buf->contentSize, &length, sizeof(length)) != EOK) {
        IAM_LOGE("copy length fail");
        return RESULT_GENERAL_ERROR;
    }
    buf->contentSize += sizeof(length);
    return RESULT_SUCCESS;
}

static ResultCode WriteTlv(const AuthAttributeType type, const uint32_t length, const uint8_t *value, Buffer *buf)
{
    if (WriteTlvHead(type, length, buf) != RESULT_SUCCESS) {
        IAM_LOGE("write tlv head fail");
        return RESULT_GENERAL_ERROR;
    }

    if (memcpy_s(buf->buf + buf->contentSize, buf->maxSize - buf->contentSize, value, length) != EOK) {
        IAM_LOGE("copy buffer content fail %{public}d  %{public}d",  buf->maxSize - buf->contentSize, length);
        return RESULT_GENERAL_ERROR;
    }
    buf->contentSize += length;
    return RESULT_SUCCESS;
}

static Buffer *GetDataTlvContent(uint32_t result, uint64_t scheduleId, uint64_t subType, uint64_t templatedId,
    uint32_t remainAttempts)
{
    Buffer *ret = CreateBufferBySize(500);
    if (!IsBufferValid(ret)) {
        IAM_LOGE("create buffer fail");
        return nullptr;
    }

    constexpr int32_t zero = 0;
    constexpr uint32_t secretLen = 32;
    constexpr uint32_t secretValueLen = 100;
    constexpr uint8_t secretValue = 8;
    std::vector<uint8_t> rootSecret(secretValueLen, secretValue);
    uint32_t acl = FACE_AUTH_CAPABILITY_LEVEL;
    if (WriteTlv(ATTR_RESULT_CODE, sizeof(result), (const uint8_t *)&result, ret) != RESULT_SUCCESS ||
        WriteTlv(ATTR_TEMPLATE_ID, sizeof(templatedId), (const uint8_t *)&templatedId, ret) != RESULT_SUCCESS ||
        WriteTlv(ATTR_SCHEDULE_ID, sizeof(scheduleId), (const uint8_t *)&scheduleId, ret) != RESULT_SUCCESS ||
        WriteTlv(ATTR_PIN_SUB_TYPE, sizeof(subType), (const uint8_t *)&subType, ret) != RESULT_SUCCESS ||
        WriteTlv(ATTR_CAPABILITY_LEVEL, sizeof(acl), (const uint8_t *)&acl, ret) != RESULT_SUCCESS ||
        WriteTlv(ATTR_LOCKOUT_DURATION, sizeof(int32_t), (const uint8_t *)&zero, ret) != RESULT_SUCCESS ||
        WriteTlv(ATTR_REMAIN_ATTEMPTS, sizeof(int32_t), (const uint8_t *)&remainAttempts, ret) != RESULT_SUCCESS ||
        WriteTlv(ATTR_ROOT_SECRET, secretLen, &rootSecret[0], ret) != RESULT_SUCCESS) {
        IAM_LOGE("write tlv fail");
        DestoryBuffer(ret);
        return nullptr;
    }
    return ret;
}

static ResultCode GenerateRetTlv(const TlvRequiredPara &para, Buffer *retTlv)
{
    if (!IsBufferValid(retTlv)) {
        IAM_LOGE("param(retTlv) is invalid");
        return RESULT_GENERAL_ERROR;
    }
    if (!IsEd25519KeyPairValid(g_keyPair)) {
        IAM_LOGE("param(g_keyPair) is invalid");
        return RESULT_GENERAL_ERROR;
    }

    IAM_LOGI("scheduleId %{public}s", GET_MASKED_STRING(para.scheduleId).c_str());
    Buffer *dataContent = GetDataTlvContent(para.result, para.scheduleId, para.subType, para.templateId,
        para.remainAttempts);
    if (!IsBufferValid(dataContent)) {
        IAM_LOGE("get data content fail");
        return RESULT_GENERAL_ERROR;
    }

    Buffer *signContent = nullptr;
    if (Ed25519Sign(g_keyPair, dataContent, &signContent) != RESULT_SUCCESS) {
        IAM_LOGE("sign data fail");
        DestoryBuffer(dataContent);
        return RESULT_GENERAL_ERROR;
    }

    uint32_t rootLen = TAG_AND_LEN_BYTE + dataContent->contentSize + TAG_AND_LEN_BYTE + ED25519_FIX_SIGN_BUFFER_SIZE;
    if (WriteTlvHead(ATTR_ROOT, rootLen, retTlv) != RESULT_SUCCESS ||
        WriteTlv(ATTR_DATA, dataContent->contentSize, dataContent->buf, retTlv) != RESULT_SUCCESS ||
        WriteTlv(ATTR_SIGNATURE, signContent->contentSize, signContent->buf, retTlv) != RESULT_SUCCESS) {
        IAM_LOGE("write tlv fail");
        DestoryBuffer(dataContent);
        DestoryBuffer(signContent);
        return RESULT_GENERAL_ERROR;
    }
    DestoryBuffer(dataContent);
    DestoryBuffer(signContent);
    return RESULT_SUCCESS;
}

ResultCode GetExecutorResultTlv(const TlvRequiredPara &para, std::vector<uint8_t> &resultTlv)
{
    Buffer *retTlv = CreateBufferBySize(RESULT_TLV_LEN);
    if (retTlv == nullptr) {
        IAM_LOGE("CreateBufferBySize failed");
        return RESULT_GENERAL_ERROR;
    }

    ResultCode ret = GenerateRetTlv(para, retTlv);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("GenerateRetTlv fail");
        return RESULT_GENERAL_ERROR;
    }

    resultTlv.resize(retTlv->contentSize);
    if (memcpy_s(&resultTlv[0], retTlv->contentSize, retTlv->buf, retTlv->contentSize) != EOK) {
        IAM_LOGE("copy retTlv to resultTlv fail");
        return RESULT_GENERAL_ERROR;
    }
    IAM_LOGI("get result tlv success");
    return RESULT_SUCCESS;
}

ResultCode GetExecutorPublicKey(std::vector<uint8_t> &vPubKey)
{
    if (!IsEd25519KeyPairValid(g_keyPair)) {
        GenerateExecutorKeyPair();
    }
    if (g_keyPair == nullptr) {
        IAM_LOGE("key pair is invalid");
        return RESULT_GENERAL_ERROR;
    }
    Buffer *pubKey = g_keyPair->pubKey;
    vPubKey.resize(pubKey->contentSize);
    if (memcpy_s(&vPubKey[0], pubKey->contentSize, pubKey->buf, pubKey->contentSize) != EOK) {
        IAM_LOGE("copy public key fail");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS
