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

#include "v1_0/user_auth_interface_service.h"
#include <hdf_base.h>
#include "securec.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "useriam_common.h"
#include "auth_level.h"
#include "coauth_funcs.h"
#include "coauth_sign_centre.h"
#include "idm_database.h"
#include "idm_session.h"
#include "lock.h"
#include "user_auth_funcs.h"
#include "user_idm_funcs.h"

#define LOG_LABEL OHOS::UserIAM::Common::LABEL_USER_AUTH_HDI

namespace OHOS {
namespace HDI {
namespace UserAuth {
namespace V1_0 {
extern "C" IUserAuthInterface *UserAuthInterfaceImplGetInstance(void)
{
    auto userAuthInterfaceService = new (std::nothrow) UserAuthInterfaceService();
    if (userAuthInterfaceService == nullptr) {
        IAM_LOGE("userAuthInterfaceService is nullptr");
        return nullptr;
    }
    return userAuthInterfaceService;
}

int32_t UserAuthInterfaceService::Init()
{
    IAM_LOGI("start");
    OHOS::UserIAM::Common::Close();
    return OHOS::UserIAM::Common::Init();
}

static bool CopyScheduleInfo(const CoAuthSchedule *in, ScheduleInfo *out)
{
    IAM_LOGI("start");
    if (in->executorSize == 0) {
        IAM_LOGE("executorSize is zero");
        return false;
    }
    out->executors.clear();
    out->templateIds.clear();
    out->scheduleId = in->scheduleId;
    out->authType = static_cast<AuthType>(in->executors[0].authType);
    out->templateIds.push_back(in->templateId);
    out->executorType = static_cast<uint32_t>(in->authSubType);
    out->scheduleMode = static_cast<uint32_t>(in->scheduleMode);
    for (uint32_t i = 0; i < in->executorSize; i++) {
        ExecutorInfo temp = {};
        temp.index = in->executors[i].executorId;
        temp.info.authType = static_cast<AuthType>(in->executors[i].authType);
        temp.info.executorRole = static_cast<ExecutorRole>(in->executors[i].executorType);
        temp.info.executorId = 0;
        temp.info.executorType = static_cast<AuthType>(in->executors[i].authAbility);
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
    return true;
}

int32_t UserAuthInterfaceService::BeginAuthentication(uint64_t contextId, const AuthSolution &param,
    std::vector<ScheduleInfo> &infos)
{
    IAM_LOGI("start");
    if (param.challenge.size() != sizeof(uint64_t)) {
        IAM_LOGE("challenge copy failed");
        return RESULT_BAD_PARAM;
    }
    GlobalLock();
    infos.clear();
    AuthSolutionHal solutionIn = {};
    solutionIn.contextId = contextId;
    solutionIn.userId = param.userId;
    solutionIn.authType = static_cast<uint32_t>(param.authType);
    solutionIn.authTrustLevel = param.authTrustLevel;
    if (memcpy_s(&solutionIn.challenge, sizeof(uint64_t), &param.challenge[0],
        param.challenge.size()) != EOK) {
        IAM_LOGE("challenge copy failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    CoAuthSchedule *schedulesGet = nullptr;
    uint32_t scheduleNum = 0;
    int32_t ret = GenerateSolutionFunc(solutionIn, &schedulesGet, &scheduleNum);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("generate solution failed");
        GlobalUnLock();
        return ret;
    }
    for (uint32_t i = 0; i < scheduleNum; i++) {
        ScheduleInfo temp = {};
        if (!CopyScheduleInfo(schedulesGet + i, &temp)) {
            infos.clear();
            ret = RESULT_GENERAL_ERROR;
            break;
        }
        infos.push_back(temp);
    }
    free(schedulesGet);
    GlobalUnLock();
    return ret;
}

int32_t UserAuthInterfaceService::UpdateAuthenticationResult(uint64_t contextId,
    const std::vector<uint8_t> &scheduleResult, AuthResultInfo &info)
{
    IAM_LOGI("start");
    if (scheduleResult.size() == 0) {
        IAM_LOGE("param is invalid");
        info.result = RESULT_BAD_PARAM;
        return RESULT_BAD_PARAM;
    }
    GlobalLock();
    Buffer *scheduleResultBuffer = CreateBufferByData(&scheduleResult[0], scheduleResult.size());
    if (scheduleResultBuffer == nullptr) {
        IAM_LOGE("scheduleTokenBuffer is null");
        info.result = RESULT_GENERAL_ERROR;
        GlobalUnLock();
        return RESULT_NO_MEMORY;
    }
    UserAuthTokenHal authTokenHal = {};
    info.result = RequestAuthResultFunc(contextId, scheduleResultBuffer, &authTokenHal);
    if (info.result != RESULT_SUCCESS) {
        IAM_LOGE("execute func failed");
        DestoryBuffer(scheduleResultBuffer);
        GlobalUnLock();
        return info.result;
    }
    info.token.resize(sizeof(UserAuthTokenHal));
    if (memcpy_s(&info.token[0], info.token.size(), &authTokenHal, sizeof(authTokenHal)) != EOK) {
        IAM_LOGE("copy authToken failed");
        DestoryBuffer(scheduleResultBuffer);
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    DestoryBuffer(scheduleResultBuffer);
    GlobalUnLock();
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::CancelAuthentication(uint64_t contextId)
{
    IAM_LOGI("start");
    GlobalLock();
    uint32_t scheduleIdNum = 0;
    int32_t ret = CancelContextFunc(contextId, nullptr, &scheduleIdNum);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("execute func failed");
        GlobalUnLock();
        return ret;
    }
    GlobalUnLock();
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::BeginIdentification(uint64_t contextId, AuthType authType,
    const std::vector<int8_t> &challenge, uint32_t executorId, ScheduleInfo &scheduleInfo)
{
    IAM_LOGI("start");
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::UpdateIdentificationResult(uint64_t contextId,
    const std::vector<uint8_t> &scheduleResult, IdentifyResultInfo &info)
{
    IAM_LOGI("start");
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::CancelIdentification(uint64_t contextId)
{
    IAM_LOGI("start");
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::GetAuthTrustLevel(int32_t userId, AuthType authType, uint32_t &authTrustLevel)
{
    IAM_LOGI("start");
    GlobalLock();
    int32_t ret = SingleAuthTrustLevel(userId, authType, &authTrustLevel);
    GlobalUnLock();
    return ret;
}

int32_t UserAuthInterfaceService::GetValidSolution(int32_t userId, const std::vector<AuthType> &authTypes,
    uint32_t authTrustLevel, std::vector<AuthType> &validTypes)
{
    IAM_LOGI("start");
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    IAM_LOGI("start");
    GlobalLock();
    uint64_t challengeU64 = 0;
    int32_t ret = OpenEditSession(userId, &challengeU64);
    challenge.resize(sizeof(uint64_t));
    if (memcpy_s(&challenge[0], challenge.size(), &challengeU64, sizeof(uint64_t)) != EOK) {
        IAM_LOGE("challengeU64 copy failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    GlobalUnLock();
    return ret;
}

int32_t UserAuthInterfaceService::CloseSession(int32_t userId)
{
    IAM_LOGI("start");
    GlobalLock();
    int32_t ret = CloseEditSession();
    GlobalUnLock();
    return ret;
}

int32_t UserAuthInterfaceService::BeginEnrollment(int32_t userId, const std::vector<uint8_t> &authToken,
    const EnrollParam &param, ScheduleInfo &info)
{
    IAM_LOGI("start");
    if (authToken.size() != sizeof(UserAuthTokenHal) && param.authType != PIN) {
        IAM_LOGE("valid authToken is needed");
        return RESULT_BAD_PARAM;
    }
    GlobalLock();
    PermissionCheckParam checkParam = {};
    if (authToken.size() == sizeof(UserAuthTokenHal) &&
        memcpy_s(checkParam.token, AUTH_TOKEN_LEN, &authToken[0], authToken.size()) != EOK) {
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    checkParam.authType = param.authType;
    checkParam.userId = userId;
    checkParam.authSubType = static_cast<uint64_t>(param.executorType);
    CoAuthSchedule scheduleInfo = {};
    int32_t ret = CheckEnrollPermission(checkParam, &scheduleInfo.scheduleId);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("check permission failed");
        GlobalUnLock();
        return ret;
    }
    ret = GetCoAuthSchedule(&scheduleInfo);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("get schedule info failed");
        GlobalUnLock();
        return ret;
    }
    if (!CopyScheduleInfo(&scheduleInfo, &info)) {
        IAM_LOGE("copy schedule info failed");
        ret = RESULT_BAD_COPY;
    }
    GlobalUnLock();
    return ret;
}

int32_t UserAuthInterfaceService::CancelEnrollment(int32_t userId)
{
    IAM_LOGI("start");
    BreakOffCoauthSchedule();
    return RESULT_SUCCESS;
}

static void CopyCredentialInfo(const CredentialInfoHal &in, CredentialInfo &out)
{
    out.authType = static_cast<AuthType>(in.authType);
    out.credentialId = in.credentialId;
    out.templateId = in.templateId;
    out.executorType = static_cast<uint32_t>(in.authSubType);
    out.executorId = 0;
    out.index = 0;
}

int32_t UserAuthInterfaceService::UpdateEnrollmentResult(int32_t userId, const std::vector<uint8_t> &scheduleResult,
    uint64_t &credentialId, CredentialInfo &oldInfo)
{
    IAM_LOGI("start");
    if (scheduleResult.size() == 0) {
        IAM_LOGE("enrollToken is invalid");
        return RESULT_BAD_PARAM;
    }
    GlobalLock();
    Buffer *scheduleResultBuffer = CreateBufferByData(&scheduleResult[0], scheduleResult.size());
    if (scheduleResultBuffer == nullptr) {
        IAM_LOGE("scheduleTokenBuffer is null");
        GlobalUnLock();
        return RESULT_NO_MEMORY;
    }
    bool isUpdate;
    int32_t ret = GetIsUpdate(&isUpdate);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("get isUpdate failed");
        DestoryBuffer(scheduleResultBuffer);
        GlobalUnLock();
        return ret;
    }
    if (isUpdate) {
        CredentialInfoHal oldCredentialHal = {};
        ret = UpdateCredentialFunc(scheduleResultBuffer, &credentialId, &oldCredentialHal);
        CopyCredentialInfo(oldCredentialHal, oldInfo);
    } else {
        ret = AddCredentialFunc(scheduleResultBuffer, &credentialId);
    }
    DestoryBuffer(scheduleResultBuffer);
    GlobalUnLock();
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
    GlobalLock();
    CredentialDeleteParam param = {};
    if (memcpy_s(param.token, AUTH_TOKEN_LEN, &authToken[0], authToken.size()) != EOK) {
        IAM_LOGE("param token copy failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    param.userId = userId;
    param.credentialId = credentialId;
    CredentialInfoHal credentialInfoHal = {};
    int32_t ret = DeleteCredentialFunc(param, &credentialInfoHal);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("delete failed");
        GlobalUnLock();
        return ret;
    }
    CopyCredentialInfo(credentialInfoHal, info);
    GlobalUnLock();
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::GetCredential(int32_t userId, AuthType authType, std::vector<CredentialInfo> &infos)
{
    IAM_LOGI("start");
    GlobalLock();
    CredentialInfoHal *credentialInfoHals = nullptr;
    uint32_t num = 0;
    int32_t ret = QueryCredentialFunc(userId, authType, &credentialInfoHals, &num);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("query credential failed");
        GlobalUnLock();
        return ret;
    }
    for (uint32_t i = 0; i < num; i++) {
        CredentialInfo credentialInfo = {};
        CopyCredentialInfo(credentialInfoHals[i], credentialInfo);
        infos.push_back(credentialInfo);
    }
    free(credentialInfoHals);
    GlobalUnLock();
    return RESULT_SUCCESS;
}

int32_t UserAuthInterfaceService::GetSecureInfo(int32_t userId, uint64_t &secureUid, std::vector<EnrolledInfo> &infos)
{
    IAM_LOGI("start");
    GlobalLock();
    EnrolledInfoHal *enrolledInfoHals = nullptr;
    uint32_t num = 0;
    int32_t ret = GetUserSecureUidFunc(userId, &secureUid, &enrolledInfoHals, &num);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("get user secureUid failed");
        GlobalUnLock();
        return ret;
    }
    for (uint32_t i = 0; i < num; i++) {
        EnrolledInfo enrolledInfo = {};
        enrolledInfo.authType = static_cast<AuthType>(enrolledInfoHals[i].enrolledId);
        enrolledInfo.enrolledId = enrolledInfoHals[i].enrolledId;
        infos.push_back(enrolledInfo);
    }
    free(enrolledInfoHals);
    GlobalUnLock();
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
    GlobalLock();
    UserAuthTokenHal authTokenStruct = {};
    if (memcpy_s(&authTokenStruct, sizeof(UserAuthTokenHal), &authToken[0], authToken.size()) != EOK) {
        IAM_LOGE("authTokenStruct copy failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    uint64_t challenge;
    int32_t ret = GetChallenge(&challenge);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("get challenge failed");
        GlobalUnLock();
        return ret;
    }
    if (challenge != authTokenStruct.challenge || !IsValidTokenTime(authTokenStruct.time) ||
        authTokenStruct.authType != PIN || UserAuthTokenVerify(&authTokenStruct) != RESULT_SUCCESS) {
        IAM_LOGE("verify token failed");
        GlobalUnLock();
        return RESULT_BAD_SIGN;
    }
    GlobalUnLock();
    return EnforceDeleteUser(userId, deletedInfos);
}

int32_t UserAuthInterfaceService::EnforceDeleteUser(int32_t userId, std::vector<CredentialInfo> &deletedInfos)
{
    IAM_LOGI("start");
    GlobalLock();
    CredentialInfoHal *credentialInfoHals = nullptr;
    uint32_t num = 0;
    int32_t ret = DeleteUserInfo(userId, &credentialInfoHals, &num);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("query credential failed");
        GlobalUnLock();
        return ret;
    }
    RefreshValidTokenTime();
    for (uint32_t i = 0; i < num; i++) {
        CredentialInfo credentialInfo = {};
        CopyCredentialInfo(credentialInfoHals[i], credentialInfo);
        deletedInfos.push_back(credentialInfo);
    }
    free(credentialInfoHals);
    GlobalUnLock();
    return RESULT_SUCCESS;
}

static bool CopyExecutorInfo(const ExecutorRegisterInfo &in, ExecutorInfoHal &out)
{
    out.authType = in.authType;
    out.authAbility = in.executorType;
    out.esl = in.esl;
    out.executorType = in.executorRole;
    if (memcpy_s(out.pubKey, PUBLIC_KEY_LEN, &in.publicKey[0], in.publicKey.size()) != EOK) {
        IAM_LOGE("memcpy failed");
        return false;
    }
    return true;
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
    GlobalLock();
    ExecutorInfoHal executorInfoHal = {};
    CopyExecutorInfo(info, executorInfoHal);
    int32_t ret = RegisterExecutor(&executorInfoHal, &index);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("register executor failed");
        GlobalUnLock();
        return ret;
    }
    CredentialInfoHal *credentialInfos = nullptr;
    uint32_t num = 0;
    ret = QueryCredentialFromExecutor(static_cast<uint32_t>(info.authType), &credentialInfos, &num);
    if (ret != RESULT_SUCCESS) {
        IAM_LOGE("query credential failed");
        GlobalUnLock();
        return ret;
    }
    for (uint32_t i = 0; i < num; ++i) {
        templateIds.push_back(credentialInfos[i].templateId);
    }
    free(credentialInfos);
    GlobalUnLock();
    return ret;
}

int32_t UserAuthInterfaceService::DeleteExecutor(uint64_t index)
{
    IAM_LOGI("start");
    GlobalLock();
    int32_t ret = UnRegisterExecutor(index);
    GlobalUnLock();
    return ret;
}
} // V1_0
} // Userauth
} // HDI
} // OHOS
