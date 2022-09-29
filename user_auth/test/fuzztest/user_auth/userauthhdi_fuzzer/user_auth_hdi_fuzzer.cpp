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

#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_USER_AUTH_HDI

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace HDI {
namespace UserAuth {
namespace V1_0 {
namespace {
const uint32_t MAX_FUZZ_STRUCT_LEN = 20;
UserAuthInterfaceService g_service;

void FillFuzzAuthTypeVector(Parcel &parcel, vector<AuthType> &vector)
{
    uint32_t len = parcel.ReadInt32() % MAX_FUZZ_STRUCT_LEN;
    vector.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        vector[i] = static_cast<AuthType>(parcel.ReadInt32());
    }
    IAM_LOGI("success");
}

void FillFuzzExecutorRegisterInfo(Parcel &parcel, ExecutorRegisterInfo &executorRegisterInfo)
{
    executorRegisterInfo.authType = static_cast<AuthType>(parcel.ReadInt32());
    executorRegisterInfo.executorRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    executorRegisterInfo.executorSensorHint = parcel.ReadUint32();
    executorRegisterInfo.executorMatcher = parcel.ReadUint32();
    executorRegisterInfo.esl = static_cast<ExecutorSecureLevel>(parcel.ReadInt32());
    FillFuzzUint8Vector(parcel, executorRegisterInfo.publicKey);
    IAM_LOGI("success");
}

void FillFuzzExecutorInfo(Parcel &parcel, ExecutorInfo &executorInfo)
{
    executorInfo.executorIndex = parcel.ReadUint64();
    FillFuzzExecutorRegisterInfo(parcel, executorInfo.info);
    IAM_LOGI("success");
}

void FillFuzzExecutorInfoVector(Parcel &parcel, vector<ExecutorInfo> &vector)
{
    uint32_t len = parcel.ReadInt32() % MAX_FUZZ_STRUCT_LEN;
    vector.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        FillFuzzExecutorInfo(parcel, vector[i]);
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
    FillFuzzExecutorInfoVector(parcel, scheduleInfo.executors);
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

void FillFuzzAuthSolution(Parcel &parcel, AuthSolution &authSolution)
{
    authSolution.userId = parcel.ReadInt32();
    authSolution.authTrustLevel = parcel.ReadUint32();
    authSolution.authType = static_cast<AuthType>(parcel.ReadInt32());
    authSolution.executorSensorHint = parcel.ReadUint32();
    FillFuzzUint8Vector(parcel, authSolution.challenge);
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
    IAM_LOGI("success");
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
    g_service.Init();
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
    int32_t userId = parcel.ReadInt32();
    std::vector<uint8_t> authToken;
    FillFuzzUint8Vector(parcel, authToken);
    EnrollParam param;
    FillFuzzEnrollParam(parcel, param);
    ScheduleInfo info;
    FillFuzzScheduleInfo(parcel, info);
    g_service.BeginEnrollment(userId, authToken, param, info);
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
    CredentialInfo info;
    FillFuzzCredentialInfo(parcel, info);
    g_service.DeleteCredential(userId, credentialId, authToken, info);
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
    PinSubType pinSubType = static_cast<PinSubType>(parcel.ReadUint32());
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
    g_service.DeleteUser(userId, authToken, deletedInfos);
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
    AuthSolution param;
    FillFuzzAuthSolution(parcel, param);
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
    g_service.UpdateAuthenticationResult(contextId, scheduleResult, info);
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

void FuzzGetAuthTrustLevel(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    uint32_t authTrustLevel = parcel.ReadUint32();
    g_service.GetAuthTrustLevel(userId, authType, authTrustLevel);
    IAM_LOGI("end");
}

void FuzzGetValidSolution(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    std::vector<AuthType> authTypes;
    FillFuzzAuthTypeVector(parcel, authTypes);
    uint32_t authTrustLevel = parcel.ReadUint32();
    std::vector<AuthType> validTypes;
    FillFuzzAuthTypeVector(parcel, validTypes);
    g_service.GetValidSolution(userId, authTypes, authTrustLevel, validTypes);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzInit);
FuzzFunc *g_fuzzFuncs[] = {FuzzInit, FuzzAddExecutor, FuzzDeleteExecutor, FuzzOpenSession, FuzzCloseSession,
    FuzzBeginEnrollment, FuzzUpdateEnrollmentResult, FuzzCancelEnrollment, FuzzDeleteCredential, FuzzGetCredential,
    FuzzGetSecureInfo, FuzzDeleteUser, FuzzEnforceDeleteUser, FuzzBeginAuthentication, FuzzUpdateAuthenticationResult,
    FuzzCancelAuthentication, FuzzBeginIdentification, FuzzUpdateIdentificationResult, FuzzCancelIdentification,
    FuzzGetAuthTrustLevel, FuzzGetValidSolution};

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
} // namespace V1_0
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::HDI::UserAuth::V1_0::UserAuthHdiFuzzTest(data, size);
    return 0;
}
