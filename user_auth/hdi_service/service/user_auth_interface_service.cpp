/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "v2_0/user_auth_interface_service.h"

#include <cinttypes>
#include <mutex>
#include <hdf_base.h>
#include "securec.h"
#include <set>
#include <string>

#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#include "adaptor_time.h"
#include "useriam_common.h"
#include "auth_level.h"
#include "buffer.h"
#include "coauth_funcs.h"
#include "executor_message.h"
#include "hmac_key.h"
#include "identify_funcs.h"
#include "idm_database.h"
#include "idm_session.h"
#include "ed25519_key.h"
#include "udid_manager.h"
#include "user_auth_hdi.h"
#include "user_auth_funcs.h"
#include "user_idm_funcs.h"
#include "enroll_specification_check.h"

#undef LOG_TAG
#define LOG_TAG "USER_AUTH_HDI"

namespace OHOS {
namespace HDI {
namespace UserAuth {
namespace {
static std::mutex g_mutex;
static std::string g_localUdid;
constexpr uint32_t INVALID_CAPABILITY_LEVEL = 100;
const std::string SCREEN_LOCK_NAME = "com.ohos.systemui";
const std::string SETTRINGS_NAME = "com.ohos.settings";

enum UserAuthCallerType : int32_t {
    TOKEN_INVALID = -1,
    TOKEN_HAP = 0,
    TOKEN_NATIVE,
};
const uint32_t PUBLIC_KEY_STR_LEN = 33;
void FormatHexString(uint8_t* data, int32_t dataSize, char* outBuffer, int32_t outBufferSize)
{
    int32_t writeIndex = 0;
    do {
        for (int i = 0; i < dataSize; i++) {
            int ret = sprintf_s(outBuffer + writeIndex, outBufferSize - writeIndex, "%X", data[i]);
            if (ret < 0) {
                writeIndex = 0;
                break;
            }
            writeIndex += ret;
        }
    } while (0);

    if (writeIndex == 0) {
        memset_s(outBuffer, outBufferSize, 0, outBufferSize);
    }
}
} // namespace

using namespace std;

extern "C" IUserAuthInterface *UserAuthInterfaceImplGetInstance(void)
{
    auto userAuthInterfaceService = new (std::nothrow) UserAuthInterfaceService();
    if (userAuthInterfaceService == nullptr) {
        IAM_LOGE("userAuthInterfaceService is nullptr");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    OHOS::UserIam::Common::Init();
    return userAuthInterfaceService;
}

int32_t UserAuthInterfaceService::Init(const std::string &deviceUdid)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    g_localUdid = deviceUdid;
    bool ret = SetLocalUdid(g_localUdid.c_str());
    IF_TRUE_LOGE_AND_RETURN_VAL(!ret, HDF_FAILURE);
    OHOS::UserIam::Common::Close();
    return OHOS::UserIam::Common::Init();
}

static bool CopyScheduleInfo(const CoAuthSchedule *in, HdiScheduleInfo *out)
{
    IAM_LOGI("start");
    if (in->executorSize == 0 || (in->templateIds.data == NULL && in->templateIds.len != 0)) {
        IAM_LOGE("executorSize is zero");
        return false;
    }
    out->executorIndexes.clear();
    out->templateIds.clear();
    out->scheduleId = in->scheduleId;
    out->authType = static_cast<AuthType>(in->authType);
    for (uint32_t i = 0; i < in->templateIds.len; ++i) {
        out->templateIds.push_back(in->templateIds.data[i]);
    }
    out->executorMatcher = static_cast<uint32_t>(in->executors[0].executorMatcher);
    out->scheduleMode = static_cast<ScheduleMode>(in->scheduleMode);
    for (uint32_t i = 0; i < in->executorSize; ++i) {
        out->executorIndexes.push_back(in->executors[i].executorIndex);
    }
    out->executorMessages.clear();
    return true;
}

static int32_t SetAttributeToCoAuthExecMsg(AuthParamHal paramHal, HdiScheduleInfo &info,
    Uint8Array publicKey, Attribute *attribute)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == nullptr, RESULT_GENERAL_ERROR);

    if (SetAttributeUint64(attribute, ATTR_SCHEDULE_ID, info.scheduleId) != RESULT_SUCCESS) {
        IAM_LOGE("SetAttributeUint64 scheduleId failed");
        return RESULT_GENERAL_ERROR;
    }

    Uint8Array localUdidIn = { paramHal.localUdid, sizeof(paramHal.localUdid) };
    if (SetAttributeUint8Array(attribute, ATTR_VERIFIER_UDID, localUdidIn) != RESULT_SUCCESS) {
        IAM_LOGE("SetAttributeUint8Array verifierUdid failed");
        return RESULT_GENERAL_ERROR;
    }
    if (SetAttributeUint8Array(attribute, ATTR_LOCAL_UDID, localUdidIn) != RESULT_SUCCESS) {
        IAM_LOGE("SetAttributeUint8Array localUdid failed");
        return RESULT_GENERAL_ERROR;
    }
    Uint8Array peerUdidIn = { paramHal.collectorUdid, sizeof(paramHal.collectorUdid) };
    if (SetAttributeUint8Array(attribute, ATTR_COLLECTOR_UDID, peerUdidIn) != RESULT_SUCCESS) {
        IAM_LOGE("SetAttributeUint8Array collectorUdid failed");
        return RESULT_GENERAL_ERROR;
    }
    if (SetAttributeUint8Array(attribute, ATTR_PEER_UDID, peerUdidIn) != RESULT_SUCCESS) {
        IAM_LOGE("SetAttributeUint8Array peerUdid failed");
        return RESULT_GENERAL_ERROR;
    }
    char publicKeyStrBuffer[PUBLIC_KEY_STR_LEN] = {0};
    FormatHexString(&publicKey.data[0], publicKey.len, publicKeyStrBuffer, PUBLIC_KEY_STR_LEN);
    IAM_LOGI("public key: %{public}s", publicKeyStrBuffer);
    if (SetAttributeUint8Array(attribute, ATTR_PUBLIC_KEY, publicKey) != RESULT_SUCCESS) {
        IAM_LOGE("SetAttributeUint8Array publicKey failed");
        return RESULT_GENERAL_ERROR;
    }
    Uint8Array challenge = { paramHal.challenge, CHALLENGE_LEN };
    if (SetAttributeUint8Array(attribute, ATTR_CHALLENGE, challenge) != RESULT_SUCCESS) {
        IAM_LOGE("SetAttributeUint8Array challenge failed");
        return RESULT_GENERAL_ERROR;
    }

    return RESULT_SUCCESS;
}

static int32_t SetAttributeToCollectorExecMsg(AuthParamHal paramHal, HdiScheduleInfo &info,
    Uint8Array publicKey, Uint8Array *retExtraInfo)
{
    Attribute *attribute = CreateEmptyAttribute();
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == nullptr, RESULT_GENERAL_ERROR);

    ResultCode ret = RESULT_GENERAL_ERROR;
    do {
        if (SetAttributeUint32(attribute, ATTR_TYPE, paramHal.authType) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint32 authType failed");
            break;
        }
        if (SetAttributeUint32(attribute, ATTR_EXECUTOR_MATCHER, info.executorMatcher) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64 executorMatcher failed");
            break;
        }
        if (SetAttributeInt32(attribute, ATTR_SCHEDULE_MODE, info.scheduleMode) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64 scheduleMode failed");
            break;
        }
        if (SetAttributeUint32(attribute, ATTR_EXECUTOR_ROLE, COLLECTOR) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint32 executorRole failed");
            break;
        }
        if (SetAttributeToCoAuthExecMsg(paramHal, info, publicKey, attribute) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeToCoAuthExecMsg failed");
            break;
        }

        SignParam signParam = {
            .needSignature = true,
            .keyType = KEY_TYPE_CROSS_DEVICE,
            .peerUdid = { paramHal.collectorUdid, sizeof(paramHal.collectorUdid) }
        };
        if (GetAttributeExecutorMsg(attribute, retExtraInfo, signParam) != RESULT_SUCCESS) {
            IAM_LOGE("GetAttributeExecutorMsg failed");
            break;
        }
        ret = RESULT_SUCCESS;
    } while (0);

    FreeAttribute(&attribute);
    return ret;
}

static int32_t GetCapabilityLevel(int32_t userId, HdiScheduleInfo &info, uint32_t &capabilityLevel)
{
    capabilityLevel = INVALID_CAPABILITY_LEVEL;
    LinkedList *credList = nullptr;
    int32_t ret = QueryCredentialFunc(userId, info.authType, &credList);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("query credential failed");
        return ret;
    }
    LinkedListNode *temp = credList->head;
    while (temp != nullptr) {
        if (temp->data == nullptr) {
            IAM_LOGE("list node is invalid");
            DestroyLinkedList(credList);
            return RESULT_UNKNOWN;
        }
        auto credentialHal = static_cast<CredentialInfoHal *>(temp->data);
        // Only the lowest acl is returned
        capabilityLevel = (capabilityLevel < credentialHal->capabilityLevel) ?
            capabilityLevel : credentialHal->capabilityLevel;
        temp = temp->next;
    }

    DestroyLinkedList(credList);
    return RESULT_SUCCESS;
}

static uint64_t GetExpiredSysTime(AuthParamHal paramHal)
{
    UserAuthContext *context = GetContext(paramHal.contextId);
    if (context == NULL) {
        IAM_LOGE("context is null");
        return NO_CHECK_PIN_EXPIRED_PERIOD;
    }

    if (!context->isExpiredReturnSuccess) {
        return context->authExpiredSysTime;
    }

    return NO_CHECK_PIN_EXPIRED_PERIOD;
}

static int32_t SetAttributeToVerifierExecMsg(AuthParamHal paramHal, HdiScheduleInfo &info,
    Uint8Array publicKey, Uint8Array *retExtraInfo)
{
    Attribute *attribute = CreateEmptyAttribute();
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == nullptr, RESULT_GENERAL_ERROR);

    ResultCode ret = RESULT_GENERAL_ERROR;
    do {
        Uint64Array templateIdsIn = {info.templateIds.data(), info.templateIds.size()};
        if (SetAttributeUint64Array(attribute, ATTR_TEMPLATE_ID_LIST, templateIdsIn) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64Array templateIdsIn failed");
            break;
        }
        uint32_t capabilityLevel = INVALID_CAPABILITY_LEVEL;
        int32_t result = GetCapabilityLevel(paramHal.userId, info, capabilityLevel);
        if (result != RESULT_SUCCESS) {
            IAM_LOGE("GetCapabilityLevel fail");
            return result;
        }
        if (capabilityLevel != INVALID_CAPABILITY_LEVEL &&
            SetAttributeUint32(attribute, ATTR_CAPABILITY_LEVEL, capabilityLevel) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint32 capabilityLevel failed");
            break;
        }
        if (SetAttributeUint64(attribute, ATTR_EXPIRED_SYS_TIME, GetExpiredSysTime(paramHal)) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64 authExpiredSysTime failed");
            break;
        }
        if (SetAttributeToCoAuthExecMsg(paramHal, info, publicKey, attribute) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeToCoAuthExecMsg failed");
            break;
        }

        SignParam signParam = { .needSignature = true, .keyType = KEY_TYPE_EXECUTOR };
        if (GetAttributeExecutorMsg(attribute, retExtraInfo, signParam) != RESULT_SUCCESS) {
            IAM_LOGE("GetAttributeExecutorMsg failed");
            break;
        }
        ret = RESULT_SUCCESS;
    } while (0);

    FreeAttribute(&attribute);
    return ret;
}

static int32_t SetAttributeToExtraInfo(HdiScheduleInfo &info, uint32_t capabilityLevel, uint64_t scheduleId)
{
    Attribute *attribute = CreateEmptyAttribute();
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == nullptr, RESULT_GENERAL_ERROR);

    ResultCode ret = RESULT_GENERAL_ERROR;
    do {
        Uint64Array templateIdsIn = {info.templateIds.data(), info.templateIds.size()};
        if (SetAttributeUint64Array(attribute, ATTR_TEMPLATE_ID_LIST, templateIdsIn) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64Array templateIdsIn failed");
            break;
        }
        if (capabilityLevel != INVALID_CAPABILITY_LEVEL &&
            SetAttributeUint32(attribute, ATTR_CAPABILITY_LEVEL, capabilityLevel) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint32 capabilityLevel failed");
            break;
        }
        if (SetAttributeUint64(attribute, ATTR_SCHEDULE_ID, scheduleId) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64 scheduleId failed");
            break;
        }

        info.executorMessages.resize(1);
        info.executorMessages[0].resize(MAX_EXECUTOR_MSG_LEN);
        Uint8Array retExtraInfo = { info.executorMessages[0].data(), MAX_EXECUTOR_MSG_LEN };
        SignParam signParam = { .needSignature = true, .keyType = KEY_TYPE_EXECUTOR };
        if (GetAttributeExecutorMsg(attribute, &retExtraInfo, signParam) != RESULT_SUCCESS) {
            IAM_LOGE("GetAttributeExecutorMsg failed");
            info.executorMessages.clear();
            break;
        }
        info.executorMessages[0].resize(retExtraInfo.len);
        ret = RESULT_SUCCESS;
    } while (0);

    FreeAttribute(&attribute);
    return ret;
}

static int32_t SetAttributeToAllInOneExecMsg(AuthParamHal paramHal, HdiScheduleInfo &info, Uint8Array *retExtraInfo)
{
    uint32_t capabilityLevel = INVALID_CAPABILITY_LEVEL;
    int32_t result = GetCapabilityLevel(paramHal.userId, info, capabilityLevel);
    if (result != RESULT_SUCCESS) {
        IAM_LOGE("GetCapabilityLevel fail");
        return result;
    }

    Attribute *attribute = CreateEmptyAttribute();
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == nullptr, RESULT_GENERAL_ERROR);

    ResultCode ret = RESULT_GENERAL_ERROR;
    do {
        Uint64Array templateIdsIn = {info.templateIds.data(), info.templateIds.size()};
        if (SetAttributeUint64Array(attribute, ATTR_TEMPLATE_ID_LIST, templateIdsIn) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64Array templateIdsIn failed");
            break;
        }
        if (capabilityLevel != INVALID_CAPABILITY_LEVEL &&
            SetAttributeUint32(attribute, ATTR_CAPABILITY_LEVEL, capabilityLevel) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint32 capabilityLevel failed");
            break;
        }
        if (SetAttributeUint64(attribute, ATTR_SCHEDULE_ID, info.scheduleId) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64 scheduleId failed");
            break;
        }

        if (SetAttributeUint64(attribute, ATTR_EXPIRED_SYS_TIME, GetExpiredSysTime(paramHal)) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64 authExpiredSysTime failed");
            break;
        }

        Uint8Array challenge = { paramHal.challenge, CHALLENGE_LEN };
        if (SetAttributeUint8Array(attribute, ATTR_CHALLENGE, challenge) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint8Array challenge failed");
            break;
        }

        SignParam signParam = { .needSignature = true, .keyType = KEY_TYPE_EXECUTOR };
        if (GetAttributeExecutorMsg(attribute, retExtraInfo, signParam) != RESULT_SUCCESS) {
            IAM_LOGE("GetAttributeExecutorMsg failed");
            break;
        }
        ret = RESULT_SUCCESS;
    } while (0);

    FreeAttribute(&attribute);
    return ret;
}

static int32_t GetAuthExecutorMsg(uint32_t executorRole, AuthParamHal paramHal,
    Uint8Array publicKey, HdiScheduleInfo &info, Uint8Array *retMsg)
{
    if (executorRole == COLLECTOR) {
        if (SetAttributeToCollectorExecMsg(paramHal, info, publicKey, retMsg) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeToCollectorExecMsg failed");
            return RESULT_GENERAL_ERROR;
        }
    } else if (executorRole == VERIFIER) {
        if (SetAttributeToVerifierExecMsg(paramHal, info, publicKey, retMsg) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeToVerifierExecMsg failed");
            return RESULT_GENERAL_ERROR;
        }
    } else if (executorRole == ALL_IN_ONE) {
        if (SetAttributeToAllInOneExecMsg(paramHal, info, retMsg) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeToAllInOneExecMsg fail");
            return RESULT_GENERAL_ERROR;
        }
    } else {
        IAM_LOGE("Unsupported executorRole %{public}u", executorRole);
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static bool CopyAuthScheduleInfo(AuthParamHal paramHal, const CoAuthSchedule *in, HdiScheduleInfo *out)
{
    IAM_LOGI("CopyAuthScheduleInfo start");
    if (in->executorSize == 0 || (in->templateIds.data == NULL && in->templateIds.len != 0)) {
        IAM_LOGE("executorSize is zero");
        return false;
    }
    out->executorIndexes.clear();
    out->templateIds.clear();
    out->scheduleId = in->scheduleId;
    out->authType = static_cast<AuthType>(in->authType);
    for (uint32_t i = 0; i < in->templateIds.len; ++i) {
        out->templateIds.push_back(in->templateIds.data[i]);
    }
    out->executorMatcher = static_cast<uint32_t>(in->executors[0].executorMatcher);
    out->scheduleMode = static_cast<ScheduleMode>(in->scheduleMode);

    out->executorIndexes.resize(in->executorSize);
    out->executorMessages.resize(in->executorSize);
    for (uint32_t i = 0; i < in->executorSize; ++i) {
        out->executorIndexes[i] = in->executors[i].executorIndex;
        out->executorMessages[i].resize(MAX_EXECUTOR_MSG_LEN);
        Uint8Array retExtraInfo = { out->executorMessages[i].data(), MAX_EXECUTOR_MSG_LEN };
        uint32_t executorRoleTemp = static_cast<ExecutorRole>(in->executors[i].executorRole);
        Uint8Array publicKeyInfo = { (uint8_t *)in->executors[1 - i].pubKey, PUBLIC_KEY_LEN };
        if (GetAuthExecutorMsg(executorRoleTemp, paramHal, publicKeyInfo, *out, &retExtraInfo) != RESULT_SUCCESS) {
            IAM_LOGE("GetAuthExecutorMsg failed");
            out->executorIndexes.clear();
            out->templateIds.clear();
            out->executorMessages.clear();
            return false;
        }
        out->executorMessages[i].resize(retExtraInfo.len);
    }
    return true;
}

static int32_t CopyAuthParamToHal(uint64_t contextId, const HdiAuthParam &param,
    AuthParamHal &paramHal)
{
    paramHal.contextId = contextId;
    paramHal.userId = param.baseParam.userId;
    paramHal.authType = static_cast<int32_t>(param.authType);
    paramHal.authTrustLevel = param.baseParam.authTrustLevel;
    if (!param.baseParam.challenge.empty() && memcpy_s(paramHal.challenge, CHALLENGE_LEN,
        param.baseParam.challenge.data(), param.baseParam.challenge.size()) != EOK) {
        IAM_LOGE("challenge copy failed");
        return RESULT_BAD_COPY;
    }
    paramHal.isAuthResultCached = false;
    paramHal.isExpiredReturnSuccess = false;
    if (param.baseParam.callerType == UserAuthCallerType::TOKEN_HAP &&
        param.baseParam.callerName == SCREEN_LOCK_NAME) {
        IAM_LOGI("auth result will be cached");
        paramHal.isAuthResultCached = true;
        paramHal.isExpiredReturnSuccess = true;
    } else if (param.baseParam.callerType == UserAuthCallerType::TOKEN_HAP &&
        param.baseParam.callerName == SETTRINGS_NAME) {
        paramHal.isExpiredReturnSuccess = true;
    }
    if (!param.collectorUdid.empty()) {
        if (memcpy_s(paramHal.collectorUdid, sizeof(paramHal.collectorUdid),
            (uint8_t *)param.collectorUdid.c_str(), param.collectorUdid.length()) != EOK) {
            IAM_LOGE("collectorUdid copy failed");
            return RESULT_BAD_COPY;
        }
    } else {
        Uint8Array collectorUdid = { paramHal.collectorUdid, sizeof(paramHal.collectorUdid) };
        if (!GetLocalUdid(&collectorUdid)) {
            IAM_LOGE("fill collector udid by local udid failed");
            return RESULT_GENERAL_ERROR;
        }
    }
    Uint8Array localUdid = { paramHal.localUdid, sizeof(paramHal.localUdid) };
    if (!GetLocalUdid(&localUdid)) {
        IAM_LOGE("GetLocalUdid failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::BeginAuthentication(uint64_t contextId, const HdiAuthParam &param,
    std::vector<HdiScheduleInfo> &infos)
{
    IAM_LOGI("start");
    infos.clear();
    AuthParamHal paramHal = {};
    int32_t ret = CopyAuthParamToHal(contextId, param, paramHal);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("copy CopyAuthParamToHal failed %{public}d", ret);
        return ret;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    LinkedList *schedulesGet = nullptr;
    ret = GenerateSolutionFunc(paramHal, &schedulesGet);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("generate solution failed %{public}d", ret);
        return ret;
    }
    if (schedulesGet == nullptr) {
        IAM_LOGE("get null schedule");
        return RESULT_GENERAL_ERROR;
    }
    LinkedListNode *tempNode = schedulesGet->head;
    while (tempNode != nullptr) {
        if (tempNode->data == nullptr) {
            IAM_LOGE("node data is invalid");
            DestroyLinkedList(schedulesGet);
            return RESULT_UNKNOWN;
        }
        HdiScheduleInfo temp = {};
        auto coAuthSchedule = static_cast<CoAuthSchedule *>(tempNode->data);
        if (!CopyAuthScheduleInfo(paramHal, coAuthSchedule, &temp)) {
            infos.clear();
            IAM_LOGE("copy schedule info failed");
            DestroyLinkedList(schedulesGet);
            return RESULT_GENERAL_ERROR;
        }
        infos.push_back(temp);
        tempNode = tempNode->next;
    }
    DestroyLinkedList(schedulesGet);
    return ret;
}

int32_t UserAuthInterfaceService::GetAllUserInfo(std::vector<UserInfo> &userInfos)
{
    IAM_LOGI("GetAllUserInfo mock start");
    static_cast<void>(userInfos);

    return RESULT_SUCCESS;
}

static int32_t CreateExecutorCommand(int32_t userId, HdiAuthResultInfo &info)
{
    LinkedList *executorSendMsg = nullptr;
    AuthPropertyMode authPropMode;
    if (info.result == RESULT_SUCCESS) {
        authPropMode = PROPERTY_MODE_UNFREEZE;
    } else if (info.remainAttempts == 0) {
        authPropMode = PROPERTY_MODE_FREEZE;
    } else {
        return RESULT_SUCCESS;
    }
    ResultCode ret = GetExecutorMsgList(userId, authPropMode, &executorSendMsg);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("get executor msg failed");
        return ret;
    }

    LinkedListNode *temp = executorSendMsg->head;
    while (temp != nullptr) {
        if (temp->data == nullptr) {
            IAM_LOGE("list node is invalid");
            DestroyLinkedList(executorSendMsg);
            return RESULT_UNKNOWN;
        }
        auto nodeData = static_cast<ExecutorMsg *>(temp->data);
        Buffer *nodeMsgBuffer = nodeData->msg;
        if (!IsBufferValid(nodeMsgBuffer)) {
            IAM_LOGE("node's buffer invalid");
            DestroyLinkedList(executorSendMsg);
            return RESULT_UNKNOWN;
        }
        HdiExecutorSendMsg msg = {};
        msg.executorIndex = nodeData->executorIndex;
        msg.commandId = static_cast<int32_t>(authPropMode);
        msg.msg.resize(nodeMsgBuffer->contentSize);
        if (memcpy_s(msg.msg.data(), msg.msg.size(), nodeMsgBuffer->buf, nodeMsgBuffer->contentSize) != EOK) {
            IAM_LOGE("copy failed");
            msg.msg.clear();
            DestroyLinkedList(executorSendMsg);
            return RESULT_BAD_COPY;
        }
        info.msgs.push_back(msg);
        temp = temp->next;
    }
    DestroyLinkedList(executorSendMsg);
    return RESULT_SUCCESS;
}

static int32_t CopyAuthResult(AuthResult &infoIn, UserAuthTokenHal &authTokenIn, HdiAuthResultInfo &infoOut,
    HdiEnrolledState &enrolledStateOut)
{
    IAM_LOGI("start");
    infoOut.result = infoIn.result;
    infoOut.remainAttempts = infoIn.remainTimes;
    infoOut.lockoutDuration = infoIn.freezingTime;
    enrolledStateOut.credentialDigest = infoIn.credentialDigest;
    enrolledStateOut.credentialCount = infoIn.credentialCount;
    infoOut.pinExpiredInfo = infoIn.pinExpiredInfo;
    if (infoOut.result == RESULT_SUCCESS) {
        infoOut.userId = infoIn.userId;
        infoOut.credentialId = infoIn.credentialId;
        IAM_LOGI("matched userId: %{public}d, credentialId: %{public}s.",
            infoOut.userId, GET_MASKED_STRING(infoOut.credentialId).c_str());
        infoOut.token.resize(sizeof(UserAuthTokenHal));
        if (memcpy_s(infoOut.token.data(), infoOut.token.size(), &authTokenIn, sizeof(UserAuthTokenHal)) != EOK) {
                IAM_LOGE("copy authToken failed");
                infoOut.token.clear();
                return RESULT_BAD_COPY;
        }
        if (infoIn.rootSecret != nullptr) {
            infoOut.rootSecret.resize(infoIn.rootSecret->contentSize);
            if (memcpy_s(infoOut.rootSecret.data(), infoOut.rootSecret.size(),
                infoIn.rootSecret->buf, infoIn.rootSecret->contentSize) != EOK) {
                IAM_LOGE("copy secret failed");
                infoOut.rootSecret.clear();
                infoOut.token.clear();
                return RESULT_BAD_COPY;
            }
        }
    }
    if (infoIn.remoteAuthResultMsg != nullptr) {
        infoOut.remoteAuthResultMsg.resize(infoIn.remoteAuthResultMsg->contentSize);
        if (memcpy_s(infoOut.remoteAuthResultMsg.data(), infoOut.remoteAuthResultMsg.size(),
            infoIn.remoteAuthResultMsg->buf, infoIn.remoteAuthResultMsg->contentSize) != EOK) {
            IAM_LOGE("copy remoteAuthResultMsg failed");
            infoOut.remoteAuthResultMsg.clear();
            infoOut.rootSecret.clear();
            infoOut.token.clear();
            return RESULT_BAD_COPY;
        }
    }
    infoOut.userId = infoIn.userId;
    IAM_LOGI("matched userId: %{public}d.", infoOut.userId);
    return RESULT_SUCCESS;
}

static int32_t UpdateAuthenticationResultInner(uint64_t contextId,
    const std::vector<uint8_t> &scheduleResult, HdiAuthResultInfo &info, HdiEnrolledState &enrolledState)
{
    IAM_LOGI("start");
    if (scheduleResult.size() == 0) {
        IAM_LOGE("param is invalid");
        DestroyContextbyId(contextId);
        return RESULT_BAD_PARAM;
    }
    Buffer *scheduleResultBuffer = CreateBufferByData(&scheduleResult[0], scheduleResult.size());
    if (!IsBufferValid(scheduleResultBuffer)) {
        IAM_LOGE("scheduleTokenBuffer is invalid");
        DestroyContextbyId(contextId);
        return RESULT_NO_MEMORY;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    UserAuthTokenHal authTokenHal = {};
    AuthResult authResult = {};
    int32_t funcRet = RESULT_GENERAL_ERROR;
    do {
        int32_t ret = RequestAuthResultFunc(contextId, scheduleResultBuffer, &authTokenHal, &authResult);
        DestoryBuffer(scheduleResultBuffer);
        if (ret != RESULT_SUCCESS) {
            IAM_LOGE("execute func failed");
            break;
        }
        ret = CopyAuthResult(authResult, authTokenHal, info, enrolledState);
        if (ret != RESULT_SUCCESS) {
            IAM_LOGE("Copy auth result failed");
            break;
        }
        if (authResult.authType != PIN_AUTH) {
            IAM_LOGI("type not pin");
        } else {
            IAM_LOGI("type pin");
            ret = CreateExecutorCommand(authResult.userId, info);
            if (ret != RESULT_SUCCESS) {
                IAM_LOGE("create executor command failed");
                break;
            }
        }
        funcRet = RESULT_SUCCESS;
    } while (0);

    DestroyAuthResult(&authResult);
    return funcRet;
}

int32_t UserAuthInterfaceService::UpdateAuthenticationResult(uint64_t contextId,
    const std::vector<uint8_t> &scheduleResult, HdiAuthResultInfo &info, HdiEnrolledState &enrolledState)
{
    IAM_LOGI("start");
    return UpdateAuthenticationResultInner(contextId, scheduleResult, info, enrolledState);
}

int32_t UserAuthInterfaceService::CancelAuthentication(uint64_t contextId)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    return DestroyContextbyId(contextId);
}

int32_t UserAuthInterfaceService::BeginIdentification(uint64_t contextId, int32_t authType,
    const std::vector<uint8_t> &challenge, uint32_t executorSensorHint, HdiScheduleInfo &scheduleInfo)
{
    IAM_LOGI("start");
    if (authType == PIN) {
        IAM_LOGE("param is invalid");
        return RESULT_BAD_PARAM;
    }
    IdentifyParam param = {};
    param.contextId = contextId;
    param.authType = static_cast<uint32_t>(authType);
    param.executorSensorHint = executorSensorHint;
    if (!challenge.empty() && memcpy_s(param.challenge, CHALLENGE_LEN, challenge.data(), challenge.size()) != EOK) {
        IAM_LOGE("challenge copy failed");
        return RESULT_BAD_COPY;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    LinkedList *scheduleGet = nullptr;
    int32_t ret = DoIdentify(param, &scheduleGet);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("generate solution failed");
        return ret;
    }
    if (scheduleGet == nullptr) {
        IAM_LOGE("get null schedule");
        return RESULT_GENERAL_ERROR;
    }
    if (scheduleGet->head == nullptr || scheduleGet->head->data == nullptr) {
        IAM_LOGE("scheduleGet is invalid");
        DestroyLinkedList(scheduleGet);
        return RESULT_UNKNOWN;
    }
    auto data = static_cast<CoAuthSchedule *>(scheduleGet->head->data);
    if (!CopyScheduleInfo(data, &scheduleInfo)) {
        IAM_LOGE("copy schedule failed");
        ret = RESULT_BAD_COPY;
    }
    DestroyLinkedList(scheduleGet);
    return ret;
}

int32_t UserAuthInterfaceService::UpdateIdentificationResult(uint64_t contextId,
    const std::vector<uint8_t> &scheduleResult, IdentifyResultInfo &info)
{
    IAM_LOGI("start");
    if (scheduleResult.size() == 0) {
        IAM_LOGE("param is invalid");
        return RESULT_BAD_PARAM;
    }
    Buffer *scheduleResultBuffer = CreateBufferByData(&scheduleResult[0], scheduleResult.size());
    if (!IsBufferValid(scheduleResultBuffer)) {
        IAM_LOGE("scheduleTokenBuffer is invalid");
        return RESULT_NO_MEMORY;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    UserAuthTokenHal token = {};
    int32_t ret = DoUpdateIdentify(contextId, scheduleResultBuffer, &info.userId, &token, &info.result);
    DestoryBuffer(scheduleResultBuffer);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("DoUpdateIdentify failed");
        return ret;
    }
    if (info.result == RESULT_SUCCESS) {
        info.token.resize(sizeof(UserAuthTokenHal));
        if (memcpy_s(info.token.data(), info.token.size(), &token, sizeof(token)) != EOK) {
            IAM_LOGE("copy authToken failed");
            info.token.clear();
            return RESULT_BAD_COPY;
        }
    }
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::CancelIdentification(uint64_t contextId)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    return DestroyContextbyId(contextId);
}

int32_t UserAuthInterfaceService::GetAvailableStatus(int32_t userId, int32_t authType, uint32_t authTrustLevel,
    int32_t &checkResult)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    checkResult = GetAvailableStatusFunc(userId, authType, authTrustLevel);
    if (checkResult != RESULT_SUCCESS) {
        IAM_LOGE("GetAvailableStatusFunc failed");
    }
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::GetValidSolution(int32_t userId, const std::vector<int32_t> &authTypes,
    uint32_t authTrustLevel, std::vector<int32_t> &validTypes)
{
    IAM_LOGI("start userId:%{public}d authTrustLevel:%{public}u", userId, authTrustLevel);
    int32_t result = RESULT_TYPE_NOT_SUPPORT;
    validTypes.clear();
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto &authType : authTypes) {
        int32_t checkRet = GetAvailableStatusFunc(userId, authType, authTrustLevel);
        if (checkRet == RESULT_SUCCESS) {
            IAM_LOGI("get valid authType:%{public}d", authType);
            validTypes.push_back(authType);
            continue;
        }
        switch (checkRet) {
            case RESULT_PIN_EXPIRED:
                LOG_ERROR("pin is expired");
                return RESULT_PIN_EXPIRED;
            case RESULT_TYPE_NOT_SUPPORT:
                IAM_LOGE("authType is not surport, authType: %{public}d", authType);
                continue;
            case RESULT_TRUST_LEVEL_NOT_SUPPORT:
                IAM_LOGE("GetAvailableStatus authType: %{public}d", authType);
                result = checkRet;
                continue;
            default:
                IAM_LOGE("authType does not support, authType:%{public}d, ret:%{public}d", authType, checkRet);
                result = RESULT_NOT_ENROLLED;
                continue;
        }
    }
    if (validTypes.empty()) {
        IAM_LOGE("no auth type valid");
        return result;
    }
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    challenge.resize(CHALLENGE_LEN);
    int32_t ret = OpenEditSession(userId, challenge.data(), challenge.size());
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("failed to open session");
        challenge.clear();
    }
    return ret;
}

int32_t UserAuthInterfaceService::CloseSession(int32_t userId)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    return CloseEditSession();
}

int32_t UserAuthInterfaceService::BeginEnrollment(
    const std::vector<uint8_t> &authToken, const HdiEnrollParam &param, HdiScheduleInfo &info)
{
    IAM_LOGI("start");
    if (authToken.size() != sizeof(UserAuthTokenHal) && authToken.size() != 0) {
        IAM_LOGE("authToken len is invalid");
        return RESULT_BAD_PARAM;
    }
    PermissionCheckParam checkParam = {};
    if (authToken.size() == sizeof(UserAuthTokenHal) &&
        memcpy_s(checkParam.token, AUTH_TOKEN_LEN, &authToken[0], authToken.size()) != EOK) {
        return RESULT_BAD_COPY;
    }
    checkParam.authType = param.authType;
    checkParam.userId = param.userId;
    checkParam.executorSensorHint = param.executorSensorHint;
    checkParam.userType = param.userType;
    std::lock_guard<std::mutex> lock(g_mutex);
    uint64_t scheduleId;
    int32_t ret;
    if (authToken.size() == sizeof(UserAuthTokenHal) && param.authType == PIN) {
        ret = CheckUpdatePermission(checkParam, &scheduleId);
        if (ret != RESULT_SUCCESS) {
            IAM_LOGE("check update permission failed");
            return ret;
        }
    } else {
        ret = CheckEnrollPermission(checkParam, &scheduleId);
        if (ret != RESULT_SUCCESS) {
            IAM_LOGE("check enroll permission failed");
            return ret;
        }
    }
    const CoAuthSchedule *scheduleInfo = GetCoAuthSchedule(scheduleId);
    if (scheduleInfo == nullptr) {
        IAM_LOGE("get schedule info failed");
        return RESULT_UNKNOWN;
    }
    if (!CopyScheduleInfo(scheduleInfo, &info)) {
        IAM_LOGE("copy schedule info failed");
        return RESULT_BAD_COPY;
    }
    ret = SetAttributeToExtraInfo(info, INVALID_CAPABILITY_LEVEL, scheduleId);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("SetAttributeToExtraInfo failed");
    }

    IAM_LOGI("end");
    return ret;
}

int32_t UserAuthInterfaceService::CancelEnrollment(int32_t userId)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    BreakOffCoauthSchedule();
    return RESULT_SUCCESS;
}

static void CopyCredentialInfo(const CredentialInfoHal &in, HdiCredentialInfo &out)
{
    out.authType = static_cast<AuthType>(in.authType);
    out.credentialId = in.credentialId;
    out.templateId = in.templateId;
    out.executorMatcher = in.executorMatcher;
    out.executorSensorHint = in.executorSensorHint;
    out.executorIndex = QueryCredentialExecutorIndex(in.authType, in.executorSensorHint);
}

static int32_t GetUpdateResult(int32_t userId, HdiEnrollResultInfo &info, Buffer *scheduleResultBuffer)
{
    UpdateCredentialOutput output = {};
    int32_t ret = UpdateCredentialFunc(userId, scheduleResultBuffer, &output);
    if (ret == RESULT_SUCCESS) {
        /* Only update pin have oldRootSecret and rootSecret */
        info.rootSecret.resize(ROOT_SECRET_LEN);
        if (memcpy_s(info.rootSecret.data(), ROOT_SECRET_LEN, output.rootSecret->buf, ROOT_SECRET_LEN) != EOK) {
            IAM_LOGE("failed to copy rootSecret");
            info.rootSecret.clear();
            return RESULT_BAD_COPY;
        }
        info.oldRootSecret.resize(ROOT_SECRET_LEN);
        if (memcpy_s(info.oldRootSecret.data(), ROOT_SECRET_LEN, output.oldRootSecret->buf, ROOT_SECRET_LEN) != EOK) {
            IAM_LOGE("failed to copy oldRootSecret");
            info.oldRootSecret.clear();
            DestoryBuffer(output.rootSecret);
            return RESULT_BAD_COPY;
        }
        info.credentialId = output.credentialId;
        CopyCredentialInfo(output.deletedCredential, info.oldInfo);
        DestoryBuffer(output.rootSecret);
        DestoryBuffer(output.oldRootSecret);
    }

    return ret;
}

static int32_t GetEnrollResult(int32_t userId, HdiEnrollResultInfo &info, Buffer *scheduleResultBuffer)
{
    Buffer *authToken = nullptr;
    Buffer *rootSecret = nullptr;
    int32_t ret = AddCredentialFunc(userId, scheduleResultBuffer, &info.credentialId, &rootSecret, &authToken);
    if (ret == RESULT_SUCCESS) {
        /* Only enroll pin have authToken and rootSecret */
        if (authToken != nullptr) {
            info.authToken.resize(authToken->contentSize);
            if (memcpy_s(info.authToken.data(), info.authToken.size(), authToken->buf, authToken->contentSize) != EOK) {
                IAM_LOGE("failed to copy authToken");
                info.authToken.clear();
                DestoryBuffer(authToken);
                DestoryBuffer(rootSecret);
                return RESULT_BAD_COPY;
            }
        }
        if (rootSecret != nullptr) {
            info.rootSecret.resize(rootSecret->contentSize);
            if (memcpy_s(info.rootSecret.data(), info.rootSecret.size(), rootSecret->buf,
                rootSecret->contentSize) != EOK) {
                IAM_LOGE("failed to copy rootSecret");
                info.rootSecret.clear();
                ret = RESULT_BAD_COPY;
            }
        }
    }
    DestoryBuffer(authToken);
    DestoryBuffer(rootSecret);
    return ret;
}

int32_t UserAuthInterfaceService::UpdateEnrollmentResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
    HdiEnrollResultInfo &info)
{
    IAM_LOGI("start");
    if (scheduleResult.size() == 0) {
        IAM_LOGE("enrollToken is invalid");
        return RESULT_BAD_PARAM;
    }
    Buffer *scheduleResultBuffer = CreateBufferByData(&scheduleResult[0], scheduleResult.size());
    if (scheduleResultBuffer == nullptr) {
        IAM_LOGE("scheduleTokenBuffer is null");
        return RESULT_NO_MEMORY;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    bool isUpdate;
    int32_t ret = GetIsUpdate(&isUpdate);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("get isUpdate failed");
        DestoryBuffer(scheduleResultBuffer);
        return ret;
    }
    if (isUpdate) {
        ret = GetUpdateResult(userId, info, scheduleResultBuffer);
        if (ret != RESULT_SUCCESS) {
            IAM_LOGE("GetUpdateResult failed");
        }
    } else {
        ret = GetEnrollResult(userId, info, scheduleResultBuffer);
        if (ret != RESULT_SUCCESS) {
            IAM_LOGE("GetEnrollResult failed");
        }
    }

    DestoryBuffer(scheduleResultBuffer);
    return ret;
}

int32_t UserAuthInterfaceService::DeleteCredential(int32_t userId, uint64_t credentialId,
    const std::vector<uint8_t> &authToken, CredentialInfo &info)
{
    IAM_LOGI("start");
    if (authToken.size() != sizeof(UserAuthTokenHal)) {
        IAM_LOGE("authToken len is invalid");
        return RESULT_BAD_PARAM;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    CredentialDeleteParam param = {};
    if (memcpy_s(param.token, AUTH_TOKEN_LEN, &authToken[0], authToken.size()) != EOK) {
        IAM_LOGE("param token copy failed");
        return RESULT_BAD_COPY;
    }
    param.userId = userId;
    param.credentialId = credentialId;
    CredentialInfoHal credentialInfoHal = {};
    int32_t ret = DeleteCredentialFunc(param, &credentialInfoHal);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("delete credential failed");
        return ret;
    }
    CopyCredentialInfo(credentialInfoHal, info);
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::GetCredential(int32_t userId, int32_t authType, std::vector<CredentialInfo> &infos)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    LinkedList *credList = nullptr;
    int32_t ret = QueryCredentialFunc(userId, authType, &credList);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("query credential failed");
        return ret;
    }
    infos.reserve(credList->getSize(credList));
    LinkedListNode *temp = credList->head;
    while (temp != nullptr) {
        if (temp->data == nullptr) {
            IAM_LOGE("list node is invalid");
            DestroyLinkedList(credList);
            return RESULT_UNKNOWN;
        }
        auto credentialHal = static_cast<CredentialInfoHal *>(temp->data);
        CredentialInfo credentialInfo = {};
        CopyCredentialInfo(*credentialHal, credentialInfo);
        infos.push_back(credentialInfo);
        temp = temp->next;
    }
    DestroyLinkedList(credList);
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::GetUserInfo(int32_t userId, uint64_t &secureUid, int32_t &pinSubType,
    std::vector<EnrolledInfo> &infos)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    EnrolledInfoHal *enrolledInfoHals = nullptr;
    uint32_t num = 0;
    uint64_t pinSubTypeGet;
    int32_t ret = GetUserInfoFunc(userId, &secureUid, &pinSubTypeGet, &enrolledInfoHals, &num);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("get user info failed");
        return ret;
    }
    pinSubType = static_cast<PinSubType>(pinSubTypeGet);
    for (uint32_t i = 0; i < num; ++i) {
        EnrolledInfo enrolledInfo = {};
        enrolledInfo.authType = static_cast<AuthType>(enrolledInfoHals[i].authType);
        enrolledInfo.enrolledId = enrolledInfoHals[i].enrolledId;
        infos.push_back(enrolledInfo);
    }
    free(enrolledInfoHals);
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
    std::vector<CredentialInfo> &deletedInfos, std::vector<uint8_t> &rootSecret)
{
    IAM_LOGI("start");
    if (authToken.size() != sizeof(UserAuthTokenHal)) {
        IAM_LOGE("authToken is invalid");
        return RESULT_BAD_PARAM;
    }
    UserAuthTokenHal authTokenStruct = {};
    if (memcpy_s(&authTokenStruct, sizeof(UserAuthTokenHal), &authToken[0], authToken.size()) != EOK) {
        IAM_LOGE("authTokenStruct copy failed");
        return RESULT_BAD_COPY;
    }
    int32_t ret = CheckIdmOperationToken(userId, &authTokenStruct);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("failed to verify token");
        return RESULT_VERIFY_TOKEN_FAIL;
    }
    ret = EnforceDeleteUser(userId, deletedInfos);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("oldRootSecret is invalid");
        return RESULT_GENERAL_ERROR;
    }

    rootSecret.resize(ROOT_SECRET_LEN);
    Buffer *oldRootSecret = GetCacheRootSecret(userId);
    if (!IsBufferValid(oldRootSecret)) {
        IAM_LOGE("get GetCacheRootSecret failed");
        return RESULT_GENERAL_ERROR;
    }
    if (memcpy_s(rootSecret.data(), rootSecret.size(), oldRootSecret->buf, oldRootSecret->contentSize) != EOK) {
        IAM_LOGE("rootSecret copy failed");
        ret = RESULT_BAD_COPY;
    }

    DestoryBuffer(oldRootSecret);
    return ret;
}

int32_t UserAuthInterfaceService::EnforceDeleteUser(int32_t userId, std::vector<CredentialInfo> &deletedInfos)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    LinkedList *credList = nullptr;
    int32_t ret = DeleteUserInfo(userId, &credList);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("query credential failed");
        return ret;
    }
    RefreshValidTokenTime();
    LinkedListNode *temp = credList->head;
    while (temp != nullptr) {
        if (temp->data == nullptr) {
            IAM_LOGE("list node is invalid");
            DestroyLinkedList(credList);
            return RESULT_UNKNOWN;
        }
        auto credentialHal = static_cast<CredentialInfoHal *>(temp->data);
        CredentialInfo credentialInfo = {};
        CopyCredentialInfo(*credentialHal, credentialInfo);
        deletedInfos.push_back(credentialInfo);
        temp = temp->next;
    }
    DestroyLinkedList(credList);
    return RESULT_SUCCESS;
}

static bool verifyExecutorRegisterInfo(const HdiExecutorRegisterInfo &in, ExecutorInfoHal &out)
{
    Buffer *execInfoMsg = CreateBufferByData(&in.signedRemoteExecutorInfo[0], in.signedRemoteExecutorInfo.size());
    if (!IsBufferValid(execInfoMsg)) {
        IAM_LOGE("execInfoMsg is invalid");
        return false;
    }

    bool isOk = CheckRemoteExecutorInfo(execInfoMsg, &out);
    DestoryBuffer(execInfoMsg);
    return isOk;
}

static bool CopyExecutorInfo(const HdiExecutorRegisterInfo &in, ExecutorInfoHal &out)
{
    out.authType = in.authType;
    out.executorMatcher = in.executorMatcher;
    out.esl = in.esl;
    out.maxTemplateAcl = in.maxTemplateAcl;
    out.executorRole = in.executorRole;
    out.executorSensorHint = in.executorSensorHint;
    if (memcpy_s(out.pubKey, PUBLIC_KEY_LEN, &in.publicKey[0], in.publicKey.size()) != EOK) {
        IAM_LOGE("memcpy failed");
        return false;
    }

    std::string deviceUdid = in.deviceUdid;
    if (deviceUdid.empty()) {
        deviceUdid = g_localUdid;
    }

    if (memcpy_s(out.deviceUdid, sizeof(out.deviceUdid), deviceUdid.c_str(), deviceUdid.length()) != EOK) {
        IAM_LOGE("memcpy failed");
        return false;
    }

    if (g_localUdid != deviceUdid) {
        IAM_LOGI("verify remote executor register info");
        if (!verifyExecutorRegisterInfo(in, out)) {
            IAM_LOGE("verifyExecutorRegisterInfo failed");
            return false;
        }
        IAM_LOGI("add remote executor authType %{public}d executorRole %{public}d", in.authType, in.executorRole);
    } else {
        IAM_LOGI("add local executor authType %{public}d executorRole %{public}d", in.authType, in.executorRole);
    }
    return true;
}

static int32_t ObtainReconciliationData(uint32_t authType, uint32_t sensorHint, std::vector<uint64_t> &templateIds)
{
    CredentialCondition condition = {};
    SetCredentialConditionAuthType(&condition, authType);
    SetCredentialConditionExecutorSensorHint(&condition, sensorHint);
    SetCredentiaConditionNeedCachePin(&condition);
    LinkedList *credList = QueryCredentialLimit(&condition);
    if (credList == nullptr) {
        IAM_LOGE("query credential failed");
        return RESULT_NOT_FOUND;
    }
    LinkedListNode *temp = credList->head;
    while (temp != nullptr) {
        if (temp->data == nullptr) {
            IAM_LOGE("list node is invalid");
            DestroyLinkedList(credList);
            return RESULT_UNKNOWN;
        }
        auto credentialInfo = static_cast<CredentialInfoHal *>(temp->data);
        templateIds.push_back(credentialInfo->templateId);
        temp = temp->next;
    }
    DestroyLinkedList(credList);
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::AddExecutor(const HdiExecutorRegisterInfo &info, uint64_t &index,
    std::vector<uint8_t> &publicKey, std::vector<uint64_t> &templateIds)
{
    IAM_LOGI("start");
    if (info.publicKey.size() != PUBLIC_KEY_LEN) {
        IAM_LOGE("invalid info");
        return RESULT_BAD_PARAM;
    }
    templateIds.clear();
    const Buffer *frameworkPubKey = GetPubKey();
    if (!IsBufferValid(frameworkPubKey)) {
        IAM_LOGE("get public key failed");
        return RESULT_UNKNOWN;
    }
    publicKey.resize(PUBLIC_KEY_LEN);
    if (memcpy_s(&publicKey[0], publicKey.size(), frameworkPubKey->buf, frameworkPubKey->contentSize) != EOK) {
        IAM_LOGE("copy public key failed");
        publicKey.clear();
        return RESULT_UNKNOWN;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    ExecutorInfoHal executorInfoHal = {};
    bool copyRet = CopyExecutorInfo(info, executorInfoHal);
    if (!copyRet) {
        IAM_LOGE("copy executor info failed");
        return RESULT_UNKNOWN;
    }
    int32_t ret = RegisterExecutor(&executorInfoHal, &index);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("register executor failed");
        return ret;
    }
    if (info.executorRole == ALL_IN_ONE) {
        return ObtainReconciliationData(executorInfoHal.authType, executorInfoHal.executorSensorHint, templateIds);
    }
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::DeleteExecutor(uint64_t index)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    return UnRegisterExecutor(index);
}

int32_t UserAuthInterfaceService::GetAllExtUserInfo(std::vector<ExtUserInfo> &userInfos)
{
    IAM_LOGI("start");
    UserInfoResult *userInfoResult = (UserInfoResult *)Malloc(sizeof(UserInfoResult) * MAX_USER);
    if (userInfoResult == NULL) {
        IAM_LOGE("malloc failed");
        return RESULT_GENERAL_ERROR;
    }
    uint32_t userInfoCount = 0;
    ResultCode ret = QueryAllExtUserInfoFunc(userInfoResult, MAX_USER, &userInfoCount);
    if (ret != RESULT_SUCCESS) {
        Free(userInfoResult);
        IAM_LOGE("QueryAllExtUserInfoFunc failed");
        return RESULT_GENERAL_ERROR;
    }

    for (uint32_t i = 0; i < userInfoCount; i++) {
        ExtUserInfo info = {};
        info.userId = userInfoResult[i].userId;
        info.userInfo.secureUid = userInfoResult[i].secUid;
        info.userInfo.pinSubType = static_cast<PinSubType>(userInfoResult[i].pinSubType);
        for (uint32_t j = 0; j < userInfoResult[i].enrollNum; j++) {
            EnrolledInfo enrolledInfo = {};
            enrolledInfo.authType = static_cast<AuthType>(userInfoResult[i].enrolledInfo[j].authType);
            enrolledInfo.enrolledId = userInfoResult[i].enrolledInfo[j].enrolledId;
            info.userInfo.enrolledInfos.push_back(enrolledInfo);
        }
        userInfos.push_back(info);
    }

    Free(userInfoResult);
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::GetEnrolledState(int32_t userId, int32_t authType, HdiEnrolledState &enrolledState)
{
    IAM_LOGI("start");
    EnrolledStateHal *enrolledStateHal = (EnrolledStateHal *) Malloc(sizeof(EnrolledStateHal));
    if (enrolledStateHal == NULL) {
        IAM_LOGE("malloc failed");
        return RESULT_GENERAL_ERROR;
    }
    int32_t ret = GetEnrolledStateFunc(userId, authType, enrolledStateHal);
    if (ret != RESULT_SUCCESS) {
        Free(enrolledStateHal);
        IAM_LOGE("GetEnrolledState failed");
        return ret;
    }
    enrolledState.credentialDigest = enrolledStateHal->credentialDigest;
    enrolledState.credentialCount = enrolledStateHal->credentialCount;

    Free(enrolledStateHal);
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::CheckReuseUnlockResult(const ReuseUnlockParam& param,
    ReuseUnlockInfo& info)
{
    IAM_LOGI("start reuseMode: %{public}u, reuseDuration: %{public}" PRIu64 ".", param.reuseUnlockResultMode,
        param.reuseUnlockResultDuration);
    if (param.authTypes.empty() || param.authTypes.size() > MAX_AUTH_TYPE_LEN ||
        param.reuseUnlockResultDuration == 0 || param.reuseUnlockResultDuration > REUSED_UNLOCK_TOKEN_PERIOD ||
        (param.reuseUnlockResultMode != AUTH_TYPE_RELEVANT && param.reuseUnlockResultMode != AUTH_TYPE_IRRELEVANT)) {
        IAM_LOGE("checkReuseUnlockResult bad param");
        return RESULT_BAD_PARAM;
    }
    ReuseUnlockParamHal paramHal = {};
    paramHal.userId = param.baseParam.userId;
    paramHal.authTrustLevel = param.baseParam.authTrustLevel;
    paramHal.reuseUnlockResultDuration = param.reuseUnlockResultDuration;
    paramHal.reuseUnlockResultMode = param.reuseUnlockResultMode;
    if (!param.baseParam.challenge.empty() &&
        memcpy_s(paramHal.challenge, CHALLENGE_LEN,
            param.baseParam.challenge.data(), param.baseParam.challenge.size()) != EOK) {
        IAM_LOGE("challenge copy failed");
        return RESULT_BAD_COPY;
    }
    paramHal.authTypeSize = param.authTypes.size();
    for (uint32_t i = 0; i < param.authTypes.size(); i++) {
        paramHal.authTypes[i] = static_cast<uint32_t>(param.authTypes[i]);
    }
    ReuseUnlockResult reuseResult = {};
    int32_t ret = CheckReuseUnlockResultFunc(&paramHal, &reuseResult);
    if (ret != RESULT_SUCCESS) {
        info.token.clear();
        IAM_LOGE("check reuse unlock result failed, ret:%{public}d", ret);
        return ret;
    }
    info.authType = reuseResult.authType;
    info.enrolledState.credentialDigest = reuseResult.enrolledState.credentialDigest;
    info.enrolledState.credentialCount = reuseResult.enrolledState.credentialCount;
    info.token.resize(AUTH_TOKEN_LEN);
    if (memcpy_s(info.token.data(), info.token.size(), reuseResult.token, AUTH_TOKEN_LEN) != EOK) {
        IAM_LOGE("copy authToken failed");
        info.token.clear();
        return RESULT_BAD_COPY;
    }
    IAM_LOGI("check reuse unlock result finish success");
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t>& msg)
{
    static_cast<void>(scheduleId);
    static_cast<void>(srcRole);
    static_cast<void>(msg);
    return HDF_SUCCESS;
}

int32_t UserAuthInterfaceService::RegisterMessageCallback(const sptr<IMessageCallback>& messageCallback)
{
    static_cast<void>(messageCallback);
    return HDF_SUCCESS;
}

int32_t UserAuthInterfaceService::PrepareRemoteAuth(const std::string &remoteUdid)
{
    IAM_LOGI("PrepareRemoteAuth");
    return RESULT_SUCCESS;
}

static bool CopyHdiScheduleInfo(const ScheduleInfoParam *in, HdiScheduleInfo *out)
{
    IAM_LOGI("CopyHdiScheduleInfo start");
    out->executorIndexes.clear();
    out->templateIds.clear();
    out->executorMessages.clear();
    out->scheduleId = in->scheduleId;
    out->authType = static_cast<AuthType>(in->authType);
    out->executorMatcher = static_cast<uint32_t>(in->executorMatcher);
    out->scheduleMode = static_cast<ScheduleMode>(in->scheduleMode);
    out->executorIndexes.push_back(in->executorIndex);
    out->executorMessages.resize(1);
    out->executorMessages[0].resize(in->executorMessages->contentSize);
    if (memcpy_s(out->executorMessages[0].data(), out->executorMessages[0].size(),
        in->executorMessages->buf, in->executorMessages->contentSize) != EOK) {
        IAM_LOGE("copy executorMessages failed");
        out->executorMessages.clear();
        out->executorIndexes.clear();
        return false;
    }
    return true;
}

static void DestroyScheduleInfoParam(ScheduleInfoParam *result)
{
    if (result == NULL) {
        return;
    }
    if (result->executorMessages != NULL) {
        DestoryBuffer(result->executorMessages);
    }
    Free(result);
}

int32_t UserAuthInterfaceService::GetLocalScheduleFromMessage(const std::string &remoteUdid,
    const std::vector<uint8_t> &message, HdiScheduleInfo& scheduleInfo)
{
    IAM_LOGI("GetLocalScheduleFromMessage start");
    if ((g_localUdid.empty()) || (remoteUdid.empty()) || (message.size() == 0)) {
        IAM_LOGE("param is invalid");
        return RESULT_BAD_PARAM;
    }
    Buffer *messageBuffer = CreateBufferByData(&message[0], message.size());
    if (!IsBufferValid(messageBuffer)) {
        IAM_LOGE("messageBuffer is invalid");
        return RESULT_NO_MEMORY;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    ScheduleInfoParam *scheduleParam = (ScheduleInfoParam *)Malloc(sizeof(ScheduleInfoParam));
    if (scheduleParam == NULL) {
        IAM_LOGE("schedule is null");
        DestoryBuffer(messageBuffer);
        return RESULT_GENERAL_ERROR;
    }

    int32_t funcRet = RESULT_GENERAL_ERROR;
    int32_t ret = RESULT_GENERAL_ERROR;
    Uint8Array remoteUdidArray = {};
    if (memcpy_s(scheduleParam->localUdid, sizeof(scheduleParam->localUdid), g_localUdid.c_str(),
        g_localUdid.length()) != EOK) {
        IAM_LOGE("localUdid copy failed");
        goto FAIL;
    }

    if (memcpy_s(scheduleParam->remoteUdid, sizeof(scheduleParam->remoteUdid), remoteUdid.c_str(),
        remoteUdid.length()) != EOK) {
        IAM_LOGE("remoteUdid copy failed");
        goto FAIL;
    }

    remoteUdidArray = { scheduleParam->remoteUdid, sizeof(scheduleParam->remoteUdid) };

    ret = GenerateScheduleFunc(messageBuffer, remoteUdidArray, scheduleParam);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("GenerateScheduleFunc failed");
        goto FAIL;
    }
    if (!CopyHdiScheduleInfo(scheduleParam, &scheduleInfo)) {
        IAM_LOGE("copy schedule info failed");
        goto FAIL;
    }

    funcRet = RESULT_SUCCESS;
FAIL:
    DestoryBuffer(messageBuffer);
    DestroyScheduleInfoParam(scheduleParam);
    return funcRet;
}

static void DestroyExecutorInfo(void *data)
{
    if (data == NULL) {
        IAM_LOGE("data is null");
        return;
    }
    Free(data);
}

int32_t UserAuthInterfaceService::GetSignedExecutorInfo(const std::vector<int32_t>& authTypes, int32_t executorRole,
    const std::string& remoteUdid, std::vector<uint8_t>& signedExecutorInfo)
{
    IAM_LOGI("GetSignedExecutorInfo start");
    if ((g_localUdid.empty()) || (remoteUdid.empty()) || (authTypes.size() == 0)) {
        IAM_LOGE("param is invalid");
        return RESULT_BAD_PARAM;
    }
    ResultCode result = RESULT_GENERAL_ERROR;
    LinkedList *linkedList = CreateLinkedList(DestroyExecutorInfo);
    if (linkedList == NULL) {
        IAM_LOGE("create linkedList failed");
        return result;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    for (uint32_t i = 0; i < authTypes.size(); i++) {
        result = GetExecutorInfoLinkedList(authTypes[i], executorRole, linkedList);
        if (result != RESULT_SUCCESS) {
            IAM_LOGE("GetExecutorInfo failed");
            DestroyLinkedList(linkedList);
            return result;
        }
    }
    uint8_t remoteUdidData[UDID_LEN] = {};
    if (memcpy_s(remoteUdidData, UDID_LEN, remoteUdid.c_str(), remoteUdid.length()) != EOK) {
        IAM_LOGE("remoteUdidData copy failed");
        DestroyLinkedList(linkedList);
        return RESULT_BAD_COPY;
    }

    Uint8Array remoteUdidArray = { remoteUdidData, sizeof(remoteUdidData) };
    Buffer *signInfo = GetSignExecutorInfoFunc(remoteUdidArray, linkedList);
    if (!IsBufferValid(signInfo)) {
        IAM_LOGE("signInfo is invalid");
        DestroyLinkedList(linkedList);
        return RESULT_NO_MEMORY;
    }
    signedExecutorInfo.resize(signInfo->contentSize);
    if (memcpy_s(&signedExecutorInfo[0], signedExecutorInfo.size(), signInfo->buf, signInfo->contentSize) != EOK) {
        IAM_LOGE("sign copy failed");
        result = RESULT_BAD_COPY;
    }
    DestoryBuffer(signInfo);
    DestroyLinkedList(linkedList);
    return result;
}

static bool CopyHdiAuthResultInfo(const AuthResultParam *in, HdiAuthResultInfo *out,
    const std::vector<uint8_t>& message)
{
    IAM_LOGI("CopyHdiAuthResultInfo start");
    out->token.clear();
    out->rootSecret.clear();
    out->remoteAuthResultMsg.clear();
    out->result = in->result;
    out->lockoutDuration = in->lockoutDuration;
    out->remainAttempts = in->remainAttempts;
    out->userId = in->userId;

    out->token.resize(in->token->contentSize);
    if (memcpy_s(out->token.data(), out->token.size(), in->token->buf, in->token->contentSize) != EOK) {
        IAM_LOGE("copy token failed");
        return false;
    }

    out->remoteAuthResultMsg.resize(message.size());
    if (memcpy_s(out->remoteAuthResultMsg.data(), out->remoteAuthResultMsg.size(),
        message.data(), message.size()) != EOK) {
        IAM_LOGE("copy remoteAuthResultMsg failed");
        return false;
    }
    return true;
}

static void DestroyAuthResultParam(AuthResultParam *result)
{
    if (result == NULL) {
        return;
    }
    if (result->token != NULL) {
        DestoryBuffer(result->token);
    }
    if (result->remoteAuthResultMsg != NULL) {
        DestoryBuffer(result->remoteAuthResultMsg);
    }
    Free(result);
}

int32_t UserAuthInterfaceService::GetAuthResultFromMessage(const std::string& remoteUdid,
    const std::vector<uint8_t>& message, HdiAuthResultInfo& authResultInfo)
{
    IAM_LOGI("GetAuthResultFromMessage start");
    if ((g_localUdid.empty()) || (remoteUdid.empty()) || (message.size() == 0)) {
        IAM_LOGE("param is invalid");
        return RESULT_BAD_PARAM;
    }
    Buffer *messageBuffer = CreateBufferByData(&message[0], message.size());
    if (!IsBufferValid(messageBuffer)) {
        IAM_LOGE("messageBuffer is invalid");
        return RESULT_NO_MEMORY;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    AuthResultParam *authResultParam = (AuthResultParam *)Malloc(sizeof(AuthResultParam));
    if (authResultParam == NULL) {
        IAM_LOGE("authResultParam is null");
        DestoryBuffer(messageBuffer);
        return RESULT_GENERAL_ERROR;
    }

    int32_t funcRet = RESULT_GENERAL_ERROR;
    int32_t ret = RESULT_GENERAL_ERROR;
    if (memcpy_s(authResultParam->localUdid, sizeof(authResultParam->localUdid), g_localUdid.c_str(),
        g_localUdid.length()) != EOK) {
        IAM_LOGE("localUdid copy failed");
        goto FAIL;
    }

    if (memcpy_s(authResultParam->remoteUdid, sizeof(authResultParam->remoteUdid), remoteUdid.c_str(),
        remoteUdid.length()) != EOK) {
        IAM_LOGE("remoteUdid copy failed");
        goto FAIL;
    }

    ret = GenerateAuthResultFunc(messageBuffer, authResultParam);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("GenerateAuthResultFunc failed");
        goto FAIL;
    }
    if (!CopyHdiAuthResultInfo(authResultParam, &authResultInfo, message)) {
        IAM_LOGE("copy authResult info failed");
        goto FAIL;
    }
    ret = CreateExecutorCommand(authResultInfo.userId, authResultInfo);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("CreateExecutorCommand failed");
        goto FAIL;
    }

    funcRet = RESULT_SUCCESS;
FAIL:
    DestoryBuffer(messageBuffer);
    DestroyAuthResultParam(authResultParam);
    return ret;
}

static int32_t CopyGlobalConfigParam(const HdiGlobalConfigParam &param, GlobalConfigParamHal &paramHal)
{
    switch (param.type) {
        case PIN_EXPIRED_PERIOD:
            paramHal.value.pinExpiredPeriod = NO_CHECK_PIN_EXPIRED_PERIOD;
            if (param.value.pinExpiredPeriod > 0) {
                paramHal.value.pinExpiredPeriod = param.value.pinExpiredPeriod;
            }
            break;
        case ENABLE_STATUS:
            paramHal.value.enableStatus = param.value.enableStatus;
            break;
        default:
            IAM_LOGE("bad global config type");
            return RESULT_BAD_PARAM;
    }
    paramHal.type = static_cast<GlobalConfigTypeHal>(param.type);

    for (uint32_t i = 0; i < param.userIds.size(); i++) {
        paramHal.userIds[i] = param.userIds[i];
    }
    paramHal.userIdNum = param.userIds.size();
    for (uint32_t i = 0; i < param.authTypes.size(); i++) {
        paramHal.authTypes[i] = static_cast<uint32_t>(param.authTypes[i]);
    }
    paramHal.authTypeNum = param.authTypes.size();
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::SetGlobalConfigParam(const HdiGlobalConfigParam &param)
{
    IAM_LOGI("start, global config type is %{public}d, userIds size %{public}zu, authTypes size %{public}zu",
        param.type, param.userIds.size(), param.authTypes.size());
    if (param.authTypes.size() > MAX_AUTH_TYPE_LEN || param.authTypes.size() == 0 ||
        param.userIds.size() > MAX_USER) {
        IAM_LOGE("SetGlobalConfigParam bad param");
        return RESULT_BAD_PARAM;
    }
    GlobalConfigParamHal paramHal = {};
    int32_t ret = CopyGlobalConfigParam(param, paramHal);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("CopyGlobalConfigParam failed");
        return ret;
    }

    ret = SetGlobalConfigParamFunc(&paramHal);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("SetGlobalConfigParamFunc failed");
    }
    return ret;
}
} // Userauth
} // HDI
} // OHOS