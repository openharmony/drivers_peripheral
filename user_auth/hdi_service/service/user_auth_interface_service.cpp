/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "v1_2/user_auth_interface_service.h"

#include <mutex>
#include <hdf_base.h>
#include "securec.h"
#include <set>

#include "iam_logger.h"
#include "iam_ptr.h"

#include "useriam_common.h"
#include "auth_level.h"
#include "buffer.h"
#include "coauth_funcs.h"
#include "identify_funcs.h"
#include "idm_database.h"
#include "idm_session.h"
#include "ed25519_key.h"
#include "user_auth_hdi.h"
#include "user_auth_funcs.h"
#include "user_idm_funcs.h"
#include "enroll_specification_check.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_USER_AUTH_HDI

namespace OHOS {
namespace HDI {
namespace UserAuth {
namespace {
static std::mutex g_mutex;
constexpr uint32_t INVALID_CAPABILITY_LEVEL = 100;
constexpr uint32_t AUTH_TRUST_LEVEL_SYS = 1;
}

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

int32_t UserAuthInterfaceService::Init()
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    OHOS::UserIam::Common::Close();
    return OHOS::UserIam::Common::Init();
}

static bool CopyScheduleInfoV1_1(const CoAuthSchedule *in, ScheduleInfoV1_1 *out)
{
    IAM_LOGI("start");
    if (in->executorSize == 0 || (in->templateIds.data == NULL && in->templateIds.len != 0)) {
        IAM_LOGE("executorSize is zero");
        return false;
    }
    out->executors.clear();
    out->templateIds.clear();
    out->scheduleId = in->scheduleId;
    out->authType = static_cast<AuthType>(in->authType);
    for (uint32_t i = 0; i < in->templateIds.len; ++i) {
        out->templateIds.push_back(in->templateIds.data[i]);
    }
    out->executorMatcher = static_cast<uint32_t>(in->executors[0].executorMatcher);
    out->scheduleMode = static_cast<ScheduleMode>(in->scheduleMode);
    for (uint32_t i = 0; i < in->executorSize; ++i) {
        ExecutorInfo temp = {};
        temp.executorIndex = in->executors[i].executorIndex;
        temp.info.authType = static_cast<AuthType>(in->executors[i].authType);
        temp.info.executorRole = static_cast<ExecutorRole>(in->executors[i].executorRole);
        temp.info.executorSensorHint = in->executors[i].executorSensorHint;
        temp.info.executorMatcher = static_cast<uint32_t>(in->executors[i].executorMatcher);
        temp.info.esl = static_cast<ExecutorSecureLevel>(in->executors[i].esl);
        temp.info.publicKey.resize(PUBLIC_KEY_LEN);
        if (memcpy_s(&temp.info.publicKey[0], temp.info.publicKey.size(),
            in->executors[i].pubKey, PUBLIC_KEY_LEN) != EOK) {
            IAM_LOGE("copy failed");
            out->executors.clear();
            out->templateIds.clear();
            return false;
        }
        out->executors.push_back(temp);
    }
    out->extraInfo = {};
    return true;
}

static int32_t SetAttributeToExtraInfo(ScheduleInfoV1_1 &info, uint32_t capabilityLevel, uint64_t scheduleId)
{
    Attribute *attribute = CreateEmptyAttribute();
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == nullptr, RESULT_GENERAL_ERROR);

    ResultCode ret = RESULT_GENERAL_ERROR;
    do {
        Uint64Array templateIdsIn = {info.templateIds.data(), info.templateIds.size()};
        if (SetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, templateIdsIn) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64Array templateIdsIn failed");
            break;
        }
        if (capabilityLevel != INVALID_CAPABILITY_LEVEL &&
            SetAttributeUint32(attribute, AUTH_CAPABILITY_LEVEL, capabilityLevel) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint32 capabilityLevel failed");
            break;
        }
        if (SetAttributeUint64(attribute, AUTH_SCHEDULE_ID, scheduleId) != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeUint64 scheduleId failed");
            break;
        }
        info.extraInfo.resize(MAX_EXECUTOR_MSG_LEN);
        Uint8Array retExtraInfo = { info.extraInfo.data(), MAX_EXECUTOR_MSG_LEN };
        if (GetAttributeExecutorMsg(attribute, true, &retExtraInfo) != RESULT_SUCCESS) {
            IAM_LOGE("GetAttributeExecutorMsg failed");
            info.extraInfo.clear();
            break;
        }
        info.extraInfo.resize(retExtraInfo.len);
        ret = RESULT_SUCCESS;
    } while (0);

    FreeAttribute(&attribute);
    return ret;
}

static int32_t GetCapabilityLevel(int32_t userId, ScheduleInfoV1_1 &info, uint32_t &capabilityLevel)
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

static int32_t SetArrayAttributeToExtraInfo(int32_t userId, std::vector<ScheduleInfoV1_1> &infos)
{
    for (auto &info : infos) {
        uint32_t capabilityLevel = INVALID_CAPABILITY_LEVEL;
        int32_t result = GetCapabilityLevel(userId, info, capabilityLevel);
        if (result != RESULT_SUCCESS) {
            IAM_LOGE("GetCapabilityLevel fail");
            return result;
        }
        result = SetAttributeToExtraInfo(info, capabilityLevel, info.scheduleId);
        if (result != RESULT_SUCCESS) {
            IAM_LOGE("SetAttributeToExtraInfo fail");
            return result;
        }
    }

    return RESULT_SUCCESS;
}

static void CopyScheduleInfoV1_1ToV1_0(const ScheduleInfoV1_1 &in, ScheduleInfo &out)
{
    out.scheduleId = in.scheduleId;
    out.templateIds = in.templateIds;
    out.authType = in.authType;
    out.executorMatcher = in.executorMatcher;
    out.scheduleMode = in.scheduleMode;
    for (auto &inInfo : in.executors) {
        ExecutorInfo outInfo = {};
        outInfo.executorIndex = inInfo.executorIndex;
        outInfo.info.authType = inInfo.info.authType;
        outInfo.info.executorRole = inInfo.info.executorRole;
        outInfo.info.executorSensorHint = inInfo.info.executorSensorHint;
        outInfo.info.executorMatcher = inInfo.info.executorMatcher;
        outInfo.info.esl = inInfo.info.esl;
        outInfo.info.publicKey = inInfo.info.publicKey;
        out.executors.push_back(outInfo);
    }
}

static void CopyScheduleInfosV1_1ToV1_0(const std::vector<ScheduleInfoV1_1> &in, std::vector<ScheduleInfo> &out)
{
    for (auto &inInfo : in) {
        ScheduleInfo outInfo;
        CopyScheduleInfoV1_1ToV1_0(inInfo, outInfo);
        out.push_back(outInfo);
    }
}

static int32_t CopyAuthSolutionV1_2ToV1_0(const AuthSolutionV1_2 &in, AuthSolution &out)
{
    out.userId = in.userId;
    out.authTrustLevel = in.authTrustLevel;
    out.authType = in.authType;
    out.executorSensorHint = in.executorSensorHint;
    out.challenge = std::move(in.challenge);
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::BeginAuthentication(uint64_t contextId, const AuthSolution &param,
    std::vector<ScheduleInfo> &infos)
{
    IAM_LOGI("start");
    std::vector<ScheduleInfoV1_1> infosV1_1;
    int32_t ret = BeginAuthenticationV1_1(contextId, param, infosV1_1);
    CopyScheduleInfosV1_1ToV1_0(infosV1_1, infos);
    return ret;
}

int32_t UserAuthInterfaceService::BeginAuthenticationV1_2(uint64_t contextId, const AuthSolutionV1_2 &paramV1_2,
    std::vector<ScheduleInfoV1_1> &infos)
{
    IAM_LOGI("start");
    AuthSolution param;
    int32_t ret = CopyAuthSolutionV1_2ToV1_0(paramV1_2, param);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("AuthSolution copy failed");
        return ret;
    }
    ret = BeginAuthenticationV1_1(contextId, param, infos);
    return ret;
}

int32_t UserAuthInterfaceService::BeginAuthenticationV1_1(
    uint64_t contextId, const AuthSolution &param, std::vector<ScheduleInfoV1_1> &infos)
{
    IAM_LOGI("start");
    infos.clear();
    AuthSolutionHal solutionIn = {};
    solutionIn.contextId = contextId;
    solutionIn.userId = param.userId;
    solutionIn.authType = static_cast<uint32_t>(param.authType);
    solutionIn.authTrustLevel = param.authTrustLevel;
    if (!param.challenge.empty() && memcpy_s(solutionIn.challenge, CHALLENGE_LEN, param.challenge.data(),
        param.challenge.size()) != EOK) {
        IAM_LOGE("challenge copy failed");
        return RESULT_BAD_COPY;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    LinkedList *schedulesGet = nullptr;
    int32_t ret = GenerateSolutionFunc(solutionIn, &schedulesGet);
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
        ScheduleInfoV1_1 temp = {};
        auto coAuthSchedule = static_cast<CoAuthSchedule *>(tempNode->data);
        if (!CopyScheduleInfoV1_1(coAuthSchedule, &temp)) {
            infos.clear();
            IAM_LOGE("copy schedule info failed");
            DestroyLinkedList(schedulesGet);
            return RESULT_GENERAL_ERROR;
        }
        infos.push_back(temp);
        tempNode = tempNode->next;
    }
    ret = SetArrayAttributeToExtraInfo(solutionIn.userId, infos);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("SetArrayAttributeToExtraInfo fail");
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

static int32_t CreateExecutorCommand(int32_t userId, AuthResultInfo &info)
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
        ExecutorSendMsg msg = {};
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

static int32_t CopyAuthResult(AuthResult &infoIn, UserAuthTokenHal &authTokenIn, AuthResultInfo &infoOut)
{
    infoOut.result = infoIn.result;
    infoOut.remainAttempts = infoIn.remainTimes;
    infoOut.lockoutDuration = infoIn.freezingTime;
    if (infoOut.result == RESULT_SUCCESS) {
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
    DestoryBuffer(infoIn.rootSecret);
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::UpdateAuthenticationResult(uint64_t contextId,
    const std::vector<uint8_t> &scheduleResult, AuthResultInfo &info)
{
    IAM_LOGI("start");
    if (scheduleResult.size() == 0) {
        IAM_LOGE("param is invalid");
        DestoryContextbyId(contextId);
        return RESULT_BAD_PARAM;
    }
    Buffer *scheduleResultBuffer = CreateBufferByData(&scheduleResult[0], scheduleResult.size());
    if (!IsBufferValid(scheduleResultBuffer)) {
        IAM_LOGE("scheduleTokenBuffer is invalid");
        DestoryContextbyId(contextId);
        return RESULT_NO_MEMORY;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    UserAuthTokenHal authTokenHal = {};
    AuthResult authResult = {};
    int32_t ret = RequestAuthResultFunc(contextId, scheduleResultBuffer, &authTokenHal, &authResult);
    DestoryBuffer(scheduleResultBuffer);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("execute func failed");
        return ret;
    }
    ret = CopyAuthResult(authResult, authTokenHal, info);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("Copy auth result failed");
        return ret;
    }
    if (authResult.authType != PIN_AUTH) {
        IAM_LOGI("type not pin");
        return RESULT_SUCCESS;
    }
    IAM_LOGI("type pin");
    return CreateExecutorCommand(authResult.userId, info);
}

int32_t UserAuthInterfaceService::CancelAuthentication(uint64_t contextId)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    return DestoryContextbyId(contextId);
}

int32_t UserAuthInterfaceService::BeginIdentification(uint64_t contextId, AuthType authType,
    const std::vector<uint8_t> &challenge, uint32_t executorSensorHint, ScheduleInfo &scheduleInfo)
{
    IAM_LOGI("start");
    ScheduleInfoV1_1 infoV1_1;
    int32_t ret = BeginIdentificationV1_1(contextId, authType, challenge, executorSensorHint, infoV1_1);
    CopyScheduleInfoV1_1ToV1_0(infoV1_1, scheduleInfo);
    return ret;
}

int32_t UserAuthInterfaceService::BeginIdentificationV1_1(uint64_t contextId, AuthType authType,
    const std::vector<uint8_t> &challenge, uint32_t executorSensorHint, ScheduleInfoV1_1 &scheduleInfo)
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
    if (!CopyScheduleInfoV1_1(data, &scheduleInfo)) {
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
    return DestoryContextbyId(contextId);
}

int32_t UserAuthInterfaceService::GetAuthTrustLevel(int32_t userId, AuthType authType, uint32_t &authTrustLevel)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> lock(g_mutex);
    int32_t ret = SingleAuthTrustLevel(userId, authType, &authTrustLevel);
    return ret;
}

int32_t UserAuthInterfaceService::GetValidSolution(int32_t userId, const std::vector<AuthType> &authTypes,
    uint32_t authTrustLevel, std::vector<AuthType> &validTypes)
{
    IAM_LOGI("start userId:%{public}d authTrustLevel:%{public}u", userId, authTrustLevel);
    int32_t result = RESULT_TYPE_NOT_SUPPORT;
    validTypes.clear();
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto &authType : authTypes) {
        uint32_t supportedAtl = AUTH_TRUST_LEVEL_SYS;
        int32_t ret = SingleAuthTrustLevel(userId, authType, &supportedAtl);
        if (ret != RESULT_SUCCESS) {
            IAM_LOGE("authType does not support, authType:%{public}d, ret:%{public}d", authType, ret);
            result = RESULT_NOT_ENROLLED;
            continue;
        }
        if (authTrustLevel > supportedAtl) {
            IAM_LOGE("authTrustLevel does not support, authType:%{public}d, supportedAtl:%{public}u",
                authType, supportedAtl);
            result = RESULT_TRUST_LEVEL_NOT_SUPPORT;
            continue;
        }
        IAM_LOGI("get valid authType:%{public}d", authType);
        validTypes.push_back(authType);
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

int32_t UserAuthInterfaceService::BeginEnrollmentV1_2(int32_t userId, const std::vector<uint8_t> &authToken,
    const EnrollParamV1_2 &paramV1_2, ScheduleInfoV1_1 &infoV1_1)
{
    IAM_LOGI("start");
    EnrollParam param;
    param.authType = paramV1_2.authType;
    param.executorSensorHint = paramV1_2.executorSensorHint;
    return BeginEnrollmentV1_1(userId, authToken, param, infoV1_1);
}


int32_t UserAuthInterfaceService::BeginEnrollment(int32_t userId, const std::vector<uint8_t> &authToken,
    const EnrollParam &param, ScheduleInfo &info)
{
    IAM_LOGI("start");
    ScheduleInfoV1_1 infoV1_1;
    int32_t ret = BeginEnrollmentV1_1(userId, authToken, param, infoV1_1);
    CopyScheduleInfoV1_1ToV1_0(infoV1_1, info);
    return ret;
}

int32_t UserAuthInterfaceService::BeginEnrollmentV1_1(
    int32_t userId, const std::vector<uint8_t> &authToken, const EnrollParam &param, ScheduleInfoV1_1 &info)
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
    checkParam.userId = userId;
    checkParam.executorSensorHint = param.executorSensorHint;
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
    if (!CopyScheduleInfoV1_1(scheduleInfo, &info)) {
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

static void CopyCredentialInfo(const CredentialInfoHal &in, CredentialInfo &out)
{
    out.authType = static_cast<AuthType>(in.authType);
    out.credentialId = in.credentialId;
    out.templateId = in.templateId;
    out.executorMatcher = in.executorMatcher;
    out.executorSensorHint = in.executorSensorHint;
    out.executorIndex = QueryCredentialExecutorIndex(in.authType, in.executorSensorHint);
}

int32_t UserAuthInterfaceService::UpdateEnrollmentResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
    EnrollResultInfo &info)
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
    Buffer *rootSecret = nullptr;
    if (isUpdate) {
        CredentialInfoHal oldCredentialHal = {};
        ret = UpdateCredentialFunc(userId, scheduleResultBuffer, &info.credentialId, &oldCredentialHal, &rootSecret);
        CopyCredentialInfo(oldCredentialHal, info.oldInfo);
    } else {
        ret = AddCredentialFunc(userId, scheduleResultBuffer, &info.credentialId, &rootSecret);
    }
    if (rootSecret != nullptr) {
        info.rootSecret.resize(rootSecret->contentSize);
        if (memcpy_s(info.rootSecret.data(), info.rootSecret.size(), rootSecret->buf, rootSecret->contentSize) != EOK) {
            IAM_LOGE("failed to copy rootSecret");
            info.rootSecret.clear();
            ret = RESULT_BAD_COPY;
        }
        DestoryBuffer(rootSecret);
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
        IAM_LOGE("delete failed");
        return ret;
    }
    CopyCredentialInfo(credentialInfoHal, info);
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::GetCredential(int32_t userId, AuthType authType, std::vector<CredentialInfo> &infos)
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

int32_t UserAuthInterfaceService::GetUserInfo(int32_t userId, uint64_t &secureUid, PinSubType &pinSubType,
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
    std::vector<CredentialInfo> &deletedInfos)
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
    return EnforceDeleteUser(userId, deletedInfos);
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

static bool CopyExecutorInfo(const ExecutorRegisterInfo &in, ExecutorInfoHal &out)
{
    out.authType = in.authType;
    out.executorMatcher = in.executorMatcher;
    out.esl = in.esl;
    out.executorRole = in.executorRole;
    out.executorSensorHint = in.executorSensorHint;
    if (memcpy_s(out.pubKey, PUBLIC_KEY_LEN, &in.publicKey[0], in.publicKey.size()) != EOK) {
        IAM_LOGE("memcpy failed");
        return false;
    }
    return true;
}

static int32_t ObtainReconciliationData(uint32_t authType, uint32_t sensorHint, std::vector<uint64_t> &templateIds)
{
    CredentialCondition condition = {};
    SetCredentialConditionAuthType(&condition, authType);
    SetCredentialConditionExecutorSensorHint(&condition, sensorHint);
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

int32_t UserAuthInterfaceService::AddExecutor(const ExecutorRegisterInfo &info, uint64_t &index,
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
    CopyExecutorInfo(info, executorInfoHal);
    int32_t ret = RegisterExecutor(&executorInfoHal, &index);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("register executor failed");
        return ret;
    }
    if (info.executorRole == VERIFIER || info.executorRole == ALL_IN_ONE) {
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
} // Userauth
} // HDI
} // OHOS
