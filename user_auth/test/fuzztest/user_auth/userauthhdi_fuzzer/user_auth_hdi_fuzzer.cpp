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

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"

#include "user_auth_hdi.h"
#include "v4_0/user_auth_interface_service.h"

#undef LOG_TAG
#define LOG_TAG "USER_AUTH_HDI"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;
using namespace OHOS::HDI::UserAuth::V4_0;

namespace OHOS {
namespace HDI {
namespace UserAuth {
namespace {
const uint32_t MAX_FUZZ_STRUCT_LEN = 20;
UserAuthInterfaceService g_service;
class DummyMessageCallback : public IMessageCallback {
public:
    ~DummyMessageCallback() override = default;

    int32_t OnMessage(uint64_t scheduleId, int32_t destRole, const std::vector<uint8_t>& msg) override
    {
        return 0;
    };
};

void FillFuzzExecutorRegisterInfo(Parcel &parcel, ExecutorRegisterInfo &executorRegisterInfo)
{
    executorRegisterInfo.authType = static_cast<AuthType>(parcel.ReadInt32());
    executorRegisterInfo.executorRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    executorRegisterInfo.executorSensorHint = parcel.ReadUint32();
    executorRegisterInfo.executorMatcher = parcel.ReadUint32();
    executorRegisterInfo.esl = static_cast<ExecutorSecureLevel>(parcel.ReadInt32());
    FillFuzzUint8Vector(parcel, executorRegisterInfo.publicKey);
    executorRegisterInfo.deviceUdid = parcel.ReadString();
    FillFuzzUint8Vector(parcel, executorRegisterInfo.signedRemoteExecutorInfo);
    IAM_LOGI("success");
}

void FillFuzzExecutorInfoIndexVector(Parcel &parcel, vector<uint64_t> &vector)
{
    uint32_t len = parcel.ReadInt32() % MAX_FUZZ_STRUCT_LEN;
    vector.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        vector[i] = parcel.ReadUint64();
    }
    IAM_LOGI("success");
}

void FillFuzzScheduleInfo(Parcel &parcel, ScheduleInfo &scheduleInfo)
{
    scheduleInfo.scheduleId = parcel.ReadUint64();
    FillFuzzUint64Vector(parcel, scheduleInfo.templateIds);
    scheduleInfo.authType = static_cast<AuthType>(parcel.ReadInt32());
    scheduleInfo.executorMatcher = parcel.ReadUint32();
    scheduleInfo.scheduleMode = static_cast<ScheduleMode>(parcel.ReadInt32());
    FillFuzzExecutorInfoIndexVector(parcel, scheduleInfo.executorIndexes);
    IAM_LOGI("success");
}

void FillFuzzScheduleInfoVector(Parcel &parcel, vector<ScheduleInfo> &vector)
{
    uint32_t len = parcel.ReadInt32() % MAX_FUZZ_STRUCT_LEN;
    vector.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        FillFuzzScheduleInfo(parcel, vector[i]);
    }
    IAM_LOGI("success");
}

void FillFuzzAuthParamBase(Parcel &parcel, AuthParamBase &authParamBase)
{
    authParamBase.userId = parcel.ReadInt32();
    authParamBase.authTrustLevel = parcel.ReadUint32();
    authParamBase.executorSensorHint = parcel.ReadUint32();
    FillFuzzUint8Vector(parcel, authParamBase.challenge);
    authParamBase.callerName = parcel.ReadString();
    authParamBase.callerType = parcel.ReadInt32();
    authParamBase.apiVersion = parcel.ReadInt32();
    IAM_LOGI("success");
}

void FillFuzzAuthParam(Parcel &parcel, AuthParam &authParam)
{
    FillFuzzAuthParamBase(parcel, authParam.baseParam);
    authParam.authType = static_cast<AuthType>(parcel.ReadInt32());
    authParam.authIntent = parcel.ReadUint32();
    if (parcel.ReadUint32() == 0) {
        authParam.isOsAccountVerified = true;
    } else {
        authParam.isOsAccountVerified = false;
    }
    authParam.collectorUdid = parcel.ReadString();
    IAM_LOGI("success");
}

void FillFuzzExecutorSendMsg(Parcel &parcel, ExecutorSendMsg &executorSendMsg)
{
    executorSendMsg.executorIndex = parcel.ReadUint32();
    FillFuzzUint8Vector(parcel, executorSendMsg.msg);
    IAM_LOGI("success");
}

void FillFuzzExecutorSendMsgVector(Parcel &parcel, vector<ExecutorSendMsg> &vector)
{
    uint32_t len = parcel.ReadInt32() % MAX_FUZZ_STRUCT_LEN;
    vector.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        FillFuzzExecutorSendMsg(parcel, vector[i]);
    }
    IAM_LOGI("success");
}

void FillFuzzAuthResultInfo(Parcel &parcel, AuthResultInfo &authResultInfo)
{
    authResultInfo.result = parcel.ReadUint32();
    authResultInfo.lockoutDuration = parcel.ReadInt32();
    authResultInfo.remainAttempts = parcel.ReadInt32();
    FillFuzzExecutorSendMsgVector(parcel, authResultInfo.msgs);
    FillFuzzUint8Vector(parcel, authResultInfo.token);
    FillFuzzUint8Vector(parcel, authResultInfo.rootSecret);
    authResultInfo.userId = parcel.ReadInt32();
    authResultInfo.credentialId = parcel.ReadUint64();
    FillFuzzUint8Vector(parcel, authResultInfo.remoteAuthResultMsg);
    IAM_LOGI("success");
}

void FillFuzzEnrolledState(Parcel &parcel, EnrolledState &enrolledState)
{
    enrolledState.credentialDigest = parcel.ReadUint64();
    enrolledState.credentialCount = parcel.ReadUint16();
    IAM_LOGI("success");
}

void FillFuzzReuseUnlockParam(Parcel &parcel, ReuseUnlockParam &param)
{
    FillFuzzAuthParamBase(parcel, param.baseParam);
    FillFuzzInt32Vector(parcel, param.authTypes);
    param.reuseUnlockResultDuration = parcel.ReadUint64();
    param.reuseUnlockResultMode = parcel.ReadInt32();
    IAM_LOGI("success");
}

void FillFuzzReuseUnlockInfo(Parcel &parcel, ReuseUnlockInfo &info)
{
    info.authType = parcel.ReadInt32();
    FillFuzzUint8Vector(parcel, info.token);
    FillFuzzEnrolledState(parcel, info.enrolledState);
}

void FillFuzzIdentifyResultInfo(Parcel &parcel, IdentifyResultInfo &identifyResultInfo)
{
    identifyResultInfo.result = parcel.ReadInt32();
    identifyResultInfo.userId = parcel.ReadInt32();
    FillFuzzUint8Vector(parcel, identifyResultInfo.token);
    IAM_LOGI("success");
}

void FillFuzzEnrollParam(Parcel &parcel, EnrollParam &enrollParam)
{
    enrollParam.authType = static_cast<AuthType>(parcel.ReadInt32());
    enrollParam.executorSensorHint = parcel.ReadUint32();
    enrollParam.callerName = parcel.ReadString();
    enrollParam.callerType = parcel.ReadInt32();
    enrollParam.apiVersion = parcel.ReadInt32();
    enrollParam.userId = parcel.ReadInt32();
    enrollParam.userType = parcel.ReadInt32();
    IAM_LOGI("success");
}

void FillFuzzGlobalConfigParam(Parcel &parcel, HdiGlobalConfigParam &configParam)
{
    configParam.value.pinExpiredPeriod = parcel.ReadUint64();
    configParam.type = parcel.ReadUint32();
    IAM_LOGI("success");
}

void FillFuzzCredentialInfo(Parcel &parcel, CredentialInfo &credentialInfo)
{
    credentialInfo.credentialId = parcel.ReadUint64();
    credentialInfo.executorIndex = parcel.ReadUint64();
    credentialInfo.templateId = parcel.ReadUint64();
    credentialInfo.authType = static_cast<AuthType>(parcel.ReadInt32());
    credentialInfo.executorMatcher = parcel.ReadUint32();
    credentialInfo.executorSensorHint = parcel.ReadUint32();
    IAM_LOGI("success");
}

void FillFuzzCredentialInfoVector(Parcel &parcel, vector<CredentialInfo> &vector)
{
    uint32_t len = parcel.ReadInt32() % MAX_FUZZ_STRUCT_LEN;
    vector.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        FillFuzzCredentialInfo(parcel, vector[i]);
    }
    IAM_LOGI("success");
}

void FillFuzzEnrolledInfo(Parcel &parcel, EnrolledInfo &enrolledInfo)
{
    enrolledInfo.enrolledId = parcel.ReadUint64();
    enrolledInfo.authType = static_cast<AuthType>(parcel.ReadInt32());
    IAM_LOGI("success");
}

void FillFuzzEnrolledInfoVector(Parcel &parcel, vector<EnrolledInfo> &vector)
{
    uint32_t len = parcel.ReadInt32() % MAX_FUZZ_STRUCT_LEN;
    vector.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        FillFuzzEnrolledInfo(parcel, vector[i]);
    }
    IAM_LOGI("success");
}

void FuzzInit(Parcel &parcel)
{
    IAM_LOGI("begin");
    g_service.Init(parcel.ReadString());
    IAM_LOGI("end");
}

void FuzzAddExecutor(Parcel &parcel)
{
    IAM_LOGI("begin");
    ExecutorRegisterInfo info;
    FillFuzzExecutorRegisterInfo(parcel, info);
    uint64_t index = parcel.ReadUint64();
    std::vector<uint8_t> publicKey;
    FillFuzzUint8Vector(parcel, publicKey);
    std::vector<uint64_t> templateIds;
    FillFuzzUint64Vector(parcel, templateIds);
    g_service.AddExecutor(info, index, publicKey, templateIds);
    IAM_LOGI("end");
}

void FuzzDeleteExecutor(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t index = parcel.ReadUint64();
    g_service.DeleteExecutor(index);
    IAM_LOGI("end");
}

void FuzzOpenSession(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    g_service.OpenSession(userId, challenge);
    IAM_LOGI("end");
}

void FuzzCloseSession(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    g_service.CloseSession(userId);
    IAM_LOGI("end");
}

void FuzzBeginEnrollment(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    EnrollParam param;
    FillFuzzEnrollParam(parcel, param);
    ScheduleInfo info;
    FillFuzzScheduleInfo(parcel, info);
    g_service.BeginEnrollment(authToken, param, info);
    IAM_LOGI("end");
}

void FuzzUpdateEnrollmentResult(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> scheduleResult;
    FillFuzzUint8Vector(parcel, scheduleResult);
    EnrollResultInfo info = {};
    FillFuzzCredentialInfo(parcel, info.oldInfo);
    info.credentialId = parcel.ReadUint64();
    FillFuzzUint8Vector(parcel, info.rootSecret);
    g_service.UpdateEnrollmentResult(userId, scheduleResult, info);
    IAM_LOGI("end");
}

void FuzzCancelEnrollment(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    g_service.CancelEnrollment(userId);
    IAM_LOGI("end");
}

void FuzzDeleteCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    uint64_t credentialId = parcel.ReadUint64();
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    HdiCredentialOperateResult operateResult;
    g_service.DeleteCredential(userId, credentialId, authToken, operateResult);
    IAM_LOGI("end");
}

void FuzzGetCredential(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    std::vector<CredentialInfo> infos;
    FillFuzzCredentialInfoVector(parcel, infos);
    g_service.GetCredential(userId, authType, infos);
    IAM_LOGI("end");
}

void FuzzGetSecureInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    uint64_t secureUid = parcel.ReadUint64();
    int32_t pinSubType = parcel.ReadInt32();
    std::vector<EnrolledInfo> infos;
    FillFuzzEnrolledInfoVector(parcel, infos);
    g_service.GetUserInfo(userId, secureUid, pinSubType, infos);
    IAM_LOGI("end");
}

void FuzzDeleteUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    std::vector<CredentialInfo> deletedInfos;
    FillFuzzCredentialInfoVector(parcel, deletedInfos);
    std::vector<uint8_t> rootSecret;
    FillFuzzUint8Vector(parcel, rootSecret);
    g_service.DeleteUser(userId, authToken, deletedInfos, rootSecret);
    IAM_LOGI("end");
}

void FuzzEnforceDeleteUser(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<CredentialInfo> deletedInfos;
    FillFuzzCredentialInfoVector(parcel, deletedInfos);
    g_service.EnforceDeleteUser(userId, deletedInfos);
    IAM_LOGI("end");
}

void FuzzBeginAuthentication(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    AuthParam param;
    FillFuzzAuthParam(parcel, param);
    std::vector<ScheduleInfo> scheduleInfos;
    FillFuzzScheduleInfoVector(parcel, scheduleInfos);
    g_service.BeginAuthentication(contextId, param, scheduleInfos);
    IAM_LOGI("end");
}

void FuzzUpdateAuthenticationResult(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    std::vector<uint8_t> scheduleResult;
    FillFuzzUint8Vector(parcel, scheduleResult);
    AuthResultInfo info;
    FillFuzzAuthResultInfo(parcel, info);
    EnrolledState enrolledState;
    FillFuzzEnrolledState(parcel, enrolledState);
    g_service.UpdateAuthenticationResult(contextId, scheduleResult, info, enrolledState);
    IAM_LOGI("end");
}

void FuzzCancelAuthentication(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    g_service.CancelAuthentication(contextId);
    IAM_LOGI("end");
}

void FuzzBeginIdentification(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    std::vector<uint8_t> challenge;
    FillFuzzUint8Vector(parcel, challenge);
    uint32_t executorId = parcel.ReadUint32();
    ScheduleInfo scheduleInfo;
    FillFuzzScheduleInfo(parcel, scheduleInfo);
    g_service.BeginIdentification(contextId, authType, challenge, executorId, scheduleInfo);
    IAM_LOGI("end");
}

void FuzzUpdateIdentificationResult(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    std::vector<uint8_t> scheduleResult;
    FillFuzzUint8Vector(parcel, scheduleResult);
    IdentifyResultInfo info;
    FillFuzzIdentifyResultInfo(parcel, info);
    g_service.UpdateIdentificationResult(contextId, scheduleResult, info);
    IAM_LOGI("end");
}

void FuzzCancelIdentification(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t contextId = parcel.ReadUint64();
    g_service.CancelIdentification(contextId);
    IAM_LOGI("end");
}

void FuzzGetAvailableStatus(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    uint32_t authTrustLevel = parcel.ReadUint32();
    int32_t checkRet = parcel.ReadInt32();
    g_service.GetAvailableStatus(userId, authType, authTrustLevel, checkRet);
    IAM_LOGI("end");
}

void FuzzGetValidSolution(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<int32_t> authTypes;
    FillFuzzInt32Vector(parcel, authTypes);
    uint32_t authTrustLevel = parcel.ReadUint32();
    std::vector<int32_t> validTypes;
    FillFuzzInt32Vector(parcel, validTypes);
    g_service.GetValidSolution(userId, authTypes, authTrustLevel, validTypes);
    IAM_LOGI("end");
}

void FuzzGetEnrolledState(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    EnrolledState enrolledState;
    FillFuzzEnrolledState(parcel, enrolledState);

    g_service.GetEnrolledState(userId, authType, enrolledState);
    IAM_LOGI("end");
}

void FuzzCheckReuseUnlockResult(Parcel &parcel)
{
    IAM_LOGI("begin");
    ReuseUnlockParam param;
    FillFuzzReuseUnlockParam(parcel, param);
    ReuseUnlockInfo info;
    FillFuzzReuseUnlockInfo(parcel, info);
    g_service.CheckReuseUnlockResult(param, info);
    IAM_LOGI("end");
}

void FuzzRegisterMessageCallback(Parcel &parcel)
{
    IAM_LOGI("begin");
    sptr<IMessageCallback> callback = nullptr;
    int32_t setCallback = parcel.ReadInt32();
    if (setCallback > 0) {
        callback = new DummyMessageCallback();
    }
    g_service.RegisterMessageCallback(callback);
    IAM_LOGI("end");
}

void FuzzSendMessage(Parcel &parcel)
{
    IAM_LOGI("begin");
    uint64_t scheduleId = parcel.ReadUint64();
    int32_t srcRole = parcel.ReadInt32();
    std::vector<uint8_t> msg;
    FillFuzzUint8Vector(parcel, msg);
    g_service.SendMessage(scheduleId, srcRole, msg);
    IAM_LOGI("end");
}

void FuzzGetLocalScheduleFromMessage(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::string remoteUdid = parcel.ReadString();
    std::vector<uint8_t> msg;
    FillFuzzUint8Vector(parcel, msg);
    ScheduleInfo scheduleInfo;
    FillFuzzScheduleInfo(parcel, scheduleInfo);
    g_service.GetLocalScheduleFromMessage(remoteUdid, msg, scheduleInfo);
    IAM_LOGI("end");
}

void FuzzGetSignedExecutorInfo(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<int32_t> authTypes;
    FillFuzzInt32Vector(parcel, authTypes);
    int32_t executorRole = parcel.ReadInt32();
    std::string remoteUdid = parcel.ReadString();
    std::vector<uint8_t> signedExecutorInfo;
    FillFuzzUint8Vector(parcel, signedExecutorInfo);
    g_service.GetSignedExecutorInfo(authTypes, executorRole, remoteUdid, signedExecutorInfo);
    IAM_LOGI("end");
}

void FuzzVerifyAuthToken(Parcel &parcel)
{
    IAM_LOGI("begin");
    std::vector<uint8_t> tokenIn;
    FillFuzzUint8Vector(parcel, tokenIn);
    uint64_t allowableDuration = parcel.ReadUint64();
    HdiUserAuthTokenPlain tokenPlain = {};
    tokenPlain.version = parcel.ReadUint32();
    tokenPlain.userId = parcel.ReadInt32();
    FillFuzzUint8Vector(parcel, tokenPlain.challenge);
    tokenPlain.timeInterval = parcel.ReadUint32();
    tokenPlain.authTrustLevel = parcel.ReadUint32();
    tokenPlain.authType = parcel.ReadInt32();
    tokenPlain.authMode = parcel.ReadInt32();
    tokenPlain.securityLevel = parcel.ReadUint32();
    tokenPlain.tokenType = parcel.ReadInt32();
    tokenPlain.secureUid = parcel.ReadUint64();
    tokenPlain.enrolledId = parcel.ReadUint64();
    tokenPlain.credentialId = parcel.ReadUint64();
    tokenPlain.collectorUdid = parcel.ReadString();
    tokenPlain.verifierUdid = parcel.ReadString();
    std::vector<uint8_t> rootSecret;
    FillFuzzUint8Vector(parcel, rootSecret);
    g_service.VerifyAuthToken(tokenIn, allowableDuration, tokenPlain, rootSecret);
    IAM_LOGI("end");
}

void FuzzSetGlobalConfigParam(Parcel &parcel)
{
    IAM_LOGI("begin");
    HdiGlobalConfigParam configParam;
    FillFuzzGlobalConfigParam(parcel, configParam);
    g_service.SetGlobalConfigParam(configParam);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzInit);
FuzzFunc *g_fuzzFuncs[] = {FuzzInit, FuzzAddExecutor, FuzzDeleteExecutor, FuzzOpenSession, FuzzCloseSession,
    FuzzBeginEnrollment, FuzzUpdateEnrollmentResult, FuzzCancelEnrollment, FuzzDeleteCredential, FuzzGetCredential,
    FuzzGetSecureInfo, FuzzDeleteUser, FuzzEnforceDeleteUser, FuzzBeginAuthentication, FuzzUpdateAuthenticationResult,
    FuzzCancelAuthentication, FuzzBeginIdentification, FuzzUpdateIdentificationResult, FuzzCancelIdentification,
    FuzzGetAvailableStatus, FuzzGetValidSolution, FuzzGetEnrolledState, FuzzCheckReuseUnlockResult,
    FuzzSendMessage, FuzzRegisterMessageCallback, FuzzGetLocalScheduleFromMessage, FuzzGetSignedExecutorInfo,
    FuzzSetGlobalConfigParam, FuzzVerifyAuthToken};

void UserAuthHdiFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::HDI::UserAuth::UserAuthHdiFuzzTest(data, size);
    return 0;
}
