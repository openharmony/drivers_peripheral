/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "user_auth_interface_service_test.h"

#include <memory>

#include "iam_ptr.h"
#include "securec.h"

#include "executor_message.h"
#include "user_auth_hdi.h"
#include "user_sign_centre.h"
#include "idm_common.h"
#include "signature_operation.h"

namespace OHOS {
namespace HDI {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::HDI::UserAuth::V4_0;
namespace {
constexpr int32_t ATL1 = 10000;
uint64_t g_pinIndex = 0;
uint64_t g_faceIndex = 0;
uint64_t g_fingerprintIndex = 0;
} // namespace

void UserAuthInterfaceServiceTest::SetUpTestCase()
{
}

void UserAuthInterfaceServiceTest::TearDownTestCase()
{
}

void UserAuthInterfaceServiceTest::SetUp()
{
}

void UserAuthInterfaceServiceTest::TearDown()
{
}

struct EnrollResultTest {
    int32_t result;
    uint64_t credentialId;
};

struct AuthResultTest {
    int32_t result;
    std::vector<uint8_t> token;
};

int32_t DoOnceExecutorRegister(const std::shared_ptr<UserAuthInterfaceService> &service, AuthType authType,
    uint64_t &index)
{
    ExecutorRegisterInfo info = {};
    info.authType = authType;
    info.executorRole = ExecutorRole::ALL_IN_ONE;
    info.esl = ExecutorSecureLevel::ESL0;
    EXPECT_EQ(GetExecutorPublicKey(info.publicKey), 0);
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIds;

    return service->AddExecutor(info, index, publicKey, templateIds);
}

void RegisterAllExecutor(const std::shared_ptr<UserAuthInterfaceService> &service)
{
    EXPECT_EQ(DoOnceExecutorRegister(service, AuthType::PIN, g_pinIndex), 0);
    EXPECT_EQ(DoOnceExecutorRegister(service, AuthType::FACE, g_faceIndex), 0);
    EXPECT_EQ(DoOnceExecutorRegister(service, AuthType::FINGERPRINT, g_fingerprintIndex), 0);
}

void DeleteAllExecutor(const std::shared_ptr<UserAuthInterfaceService> &service)
{
    EXPECT_EQ(service->DeleteExecutor(g_pinIndex), 0);
    EXPECT_EQ(service->DeleteExecutor(g_faceIndex), 0);
    EXPECT_EQ(service->DeleteExecutor(g_fingerprintIndex), 0);
}

void DoOnceEnroll(const std::shared_ptr<UserAuthInterfaceService> &service, int32_t userId, AuthType authType,
    const std::vector<uint8_t> &authToken, EnrollResultTest &enrollResultTest)
{
    EnrollParam enrollParam = {};
    enrollParam.authType = authType;
    enrollParam.userId = userId;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginEnrollment(authToken, enrollParam, scheduleInfo), 0);

    EnrollResultInfo enrolledResultInfo = {};
    std::vector<uint8_t> enrollScheduleResult;
    TlvRequiredPara para = {};
    para.result = 0;
    para.scheduleId = scheduleInfo.scheduleId;
    para.subType = 10000;
    para.templateId = 20;
    para.remainAttempts = 5;
    EXPECT_EQ(GetExecutorResultTlv(para, enrollScheduleResult), 0);

    enrollResultTest.result = service->UpdateEnrollmentResult(userId, enrollScheduleResult, enrolledResultInfo);
    enrollResultTest.credentialId = enrolledResultInfo.credentialId;
    EXPECT_EQ(enrollResultTest.result, 0);
}

void DoOnceAuth(const std::shared_ptr<UserAuthInterfaceService> &service, int32_t userId, AuthType authType,
    std::vector<uint8_t> &challenge, AuthResultTest &authResultTest)
{
    constexpr uint64_t contextId = 636548;
    AuthParam authParam = {};
    authParam.baseParam.userId = userId;
    authParam.baseParam.authTrustLevel = ATL1;
    authParam.authType = authType;
    authParam.baseParam.challenge = challenge;
    std::vector<ScheduleInfo> scheduleInfos;
    EXPECT_EQ(service->BeginAuthentication(contextId, authParam, scheduleInfos), 0);
    EXPECT_TRUE(!scheduleInfos.empty());

    std::vector<uint8_t> authScheduleResult;
    TlvRequiredPara para = {};
    para.result = 0;
    para.scheduleId = scheduleInfos[0].scheduleId;
    para.subType = 10000;
    para.templateId = 20;
    para.remainAttempts = 5;
    EXPECT_EQ(GetExecutorResultTlv(para, authScheduleResult), 0);
    AuthResultInfo authResultInfo = {};
    HdiEnrolledState enrolledState = {};

    authResultTest.result = service->UpdateAuthenticationResult(contextId, authScheduleResult, authResultInfo,
        enrolledState);
    EXPECT_EQ(authResultTest.result, 0);
    EXPECT_EQ(authResultInfo.userId, authParam.baseParam.userId);
    authResultTest.token = authResultInfo.token;
}

HWTEST_F(UserAuthInterfaceServiceTest, TestOpenSession_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);
    constexpr int32_t userId = 1245;
    constexpr uint32_t challengeSize = 32;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);
    EXPECT_EQ(challenge.size(), challengeSize);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestOpenSession_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    constexpr int32_t userId1 = 1245;
    std::vector<uint8_t> challenge1;
    EXPECT_EQ(service->OpenSession(userId1, challenge1), 0);
    EXPECT_EQ(challenge1.size(), 32);

    constexpr int32_t userId2 = 2245;
    std::vector<uint8_t> challenge2;
    EXPECT_EQ(service->OpenSession(userId2, challenge2), 0);
    EXPECT_EQ(challenge2.size(), 32);

    EXPECT_EQ(service->CloseSession(userId1), 0);
    EXPECT_EQ(service->CloseSession(userId2), 2);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestAddExecutor_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    ExecutorRegisterInfo info = {};
    uint64_t index = 0;
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIds;
    EXPECT_EQ(service->AddExecutor(info, index, publicKey, templateIds), 8);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestAddExecutor_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint32_t publicKeySize = 32;
    ExecutorRegisterInfo info = {};
    info.authType = AuthType::FACE;
    info.publicKey.resize(publicKeySize);
    uint64_t index = 0;
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIds;

    EXPECT_EQ(service->AddExecutor(info, index, publicKey, templateIds), 0);
    EXPECT_NE(index, 0);
    EXPECT_TRUE(!publicKey.empty());

    EXPECT_EQ(service->DeleteExecutor(index), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestAddExecutor_003, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint32_t publicKeySize = 32;
    ExecutorRegisterInfo info = {};
    info.authType = AuthType::FACE;
    info.publicKey.resize(publicKeySize);
    uint64_t index = 0;
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIds;

    EXPECT_EQ(service->AddExecutor(info, index, publicKey, templateIds), 0);
    EXPECT_NE(index, 0);
    EXPECT_TRUE(!publicKey.empty());

    index = 0;
    publicKey.clear();
    EXPECT_EQ(service->AddExecutor(info, index, publicKey, templateIds), 0);
    EXPECT_NE(index, 0);
    EXPECT_TRUE(!publicKey.empty());

    EXPECT_EQ(service->DeleteExecutor(index), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestDeleteExecutor_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t index1 = 1236584;
    constexpr uint64_t index2 = 9895255;
    EXPECT_EQ(service->DeleteExecutor(index1), 10006);
    EXPECT_EQ(service->DeleteExecutor(index2), 10006);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginEnrollment_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 123456;
    std::vector<uint8_t> authToken(10, 1);
    EnrollParam param = {};
    param.userId = userId;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginEnrollment(authToken, param, scheduleInfo), 8);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginEnrollment_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 123456;
    std::vector<uint8_t> authToken;
    EnrollParam param = {};
    param.userId = userId;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginEnrollment(authToken, param, scheduleInfo), RESULT_NEED_INIT);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginEnrollment_003, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 123456;

    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    std::vector<uint8_t> authToken;
    EnrollParam param = {};
    param.userId = userId;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginEnrollment(authToken, param, scheduleInfo), RESULT_TYPE_NOT_SUPPORT);

    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginEnrollment_004, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 123456;

    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    std::vector<uint8_t> authToken;
    EnrollParam param = {};
    param.userId = userId;
    param.authType = AuthType::PIN;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginEnrollment(authToken, param, scheduleInfo), 10012);

    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginEnrollment_005, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 123456;

    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    ExecutorRegisterInfo info = {};
    info.authType = AuthType::PIN;
    info.executorRole = ExecutorRole::ALL_IN_ONE;
    info.esl = ExecutorSecureLevel::ESL0;
    info.publicKey.resize(32);
    uint64_t index = 0;
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIds;

    EXPECT_EQ(service->AddExecutor(info, index, publicKey, templateIds), 0);
    EXPECT_NE(index, 0);
    EXPECT_FALSE(publicKey.empty());

    std::vector<uint8_t> authToken;
    EnrollParam param = {};
    param.userId = userId;
    param.authType = AuthType::PIN;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginEnrollment(authToken, param, scheduleInfo), 0);
    EXPECT_EQ(service->CancelEnrollment(userId), 0);

    EXPECT_EQ(service->DeleteExecutor(index), 0);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginEnrollment_006, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 123456;
    constexpr int32_t publicKeySize = 32;

    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    ExecutorRegisterInfo info = {};
    info.authType = AuthType::PIN;
    info.executorRole = ExecutorRole::ALL_IN_ONE;
    info.esl = ExecutorSecureLevel::ESL0;
    info.publicKey.resize(publicKeySize);
    uint64_t index = 0;
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIds;

    EXPECT_EQ(service->AddExecutor(info, index, publicKey, templateIds), 0);
    EXPECT_NE(index, 0);
    EXPECT_FALSE(publicKey.empty());

    constexpr uint32_t apiVersion = 10000;
    std::vector<uint8_t> authToken;
    EnrollParam param = {};
    param.userId = userId;
    param.authType = AuthType::PIN;
    param.callerName = "com.ohos.settings";
    param.apiVersion = apiVersion;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginEnrollment(authToken, param, scheduleInfo), 0);
    EXPECT_EQ(service->CancelEnrollment(userId), 0);

    EXPECT_EQ(service->DeleteExecutor(index), 0);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateEnrollmentResult_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 6978465;
    std::vector<uint8_t> scheduleResult;
    EnrollResultInfo enrolledResultInfo = {};
    EXPECT_EQ(service->UpdateEnrollmentResult(userId, scheduleResult, enrolledResultInfo), 8);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateEnrollmentResult_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 6978465;
    std::vector<uint8_t> scheduleResult(600000, 1);
    EnrollResultInfo enrolledResultInfo = {};
    EXPECT_EQ(service->UpdateEnrollmentResult(userId, scheduleResult, enrolledResultInfo), 10004);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateEnrollmentResult_003, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 6978465;
    std::vector<uint8_t> scheduleResult(100, 1);
    EnrollResultInfo enrolledResultInfo = {};
    EXPECT_EQ(service->UpdateEnrollmentResult(userId, scheduleResult, enrolledResultInfo), 10005);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateEnrollmentResult_004, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 6978465;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    std::vector<uint8_t> scheduleResult(100, 1);
    EnrollResultInfo enrolledResultInfo = {};
    EXPECT_EQ(service->UpdateEnrollmentResult(userId, scheduleResult, enrolledResultInfo), 10005);

    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateEnrollmentResult_005, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 6978465;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    ExecutorRegisterInfo info = {};
    info.authType = AuthType::PIN;
    info.executorRole = ExecutorRole::ALL_IN_ONE;
    info.esl = ExecutorSecureLevel::ESL0;
    info.publicKey.resize(32);
    uint64_t index = 0;
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIds;

    EXPECT_EQ(service->AddExecutor(info, index, publicKey, templateIds), 0);

    std::vector<uint8_t> authToken;
    EnrollParam param = {};
    param.userId = userId;
    param.authType = AuthType::PIN;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginEnrollment(authToken, param, scheduleInfo), 0);

    std::vector<uint8_t> scheduleResult(100, 1);
    EnrollResultInfo enrolledResultInfo = {};
    EXPECT_EQ(service->UpdateEnrollmentResult(userId, scheduleResult, enrolledResultInfo), 10012);

    EXPECT_EQ(service->DeleteExecutor(index), 0);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateEnrollmentResult_006, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 6978465;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestCancelEnrollment_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 6978465;
    EXPECT_EQ(service->CancelEnrollment(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestCancelEnrollment_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 6978465;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);
    EXPECT_EQ(service->CancelEnrollment(userId), 0);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginAuthentication_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t contextId = 123456;
    constexpr uint32_t challengeSize = 100;
    constexpr uint32_t apiVersion = 11;
    AuthParam param = {};
    param.baseParam.challenge.resize(challengeSize);
    param.baseParam.apiVersion = apiVersion;
    param.baseParam.callerName = "";
    param.baseParam.callerType = 0;
    std::vector<ScheduleInfo> scheduleInfos;
    EXPECT_EQ(service->BeginAuthentication(contextId, param, scheduleInfos), 10003);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginAuthentication_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t contextId = 123456;
    constexpr uint32_t challengeSize = 100;
    constexpr uint32_t apiVersion = 10000;
    AuthParam param = {};
    param.baseParam.challenge.resize(challengeSize);
    param.baseParam.apiVersion = apiVersion;
    param.baseParam.callerName = "com.ohos.systemui";
    param.baseParam.callerType = 0;
    std::vector<ScheduleInfo> scheduleInfos;
    EXPECT_EQ(service->BeginAuthentication(contextId, param, scheduleInfos), 10003);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateAuthenticationResult_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t contextId = 123456;
    std::vector<uint8_t> scheduleResult;
    AuthResultInfo authResultInfo = {};
    EnrolledState enrolledState = {};
    EXPECT_EQ(service->UpdateAuthenticationResult(contextId, scheduleResult, authResultInfo,
        enrolledState), 8);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateAuthenticationResult_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t contextId = 123456;
    std::vector<uint8_t> scheduleResult(600000, 1);
    AuthResultInfo authResultInfo = {};
    EnrolledState enrolledState = {};
    EXPECT_EQ(service->UpdateAuthenticationResult(contextId, scheduleResult, authResultInfo,
        enrolledState), 10004);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateAuthenticationResult_003, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t contextId = 123456;
    std::vector<uint8_t> scheduleResult;
    scheduleResult.resize(sizeof(ExecutorResultInfo));
    AuthResultInfo authResultInfo = {};
    EnrolledState enrolledState = {};
    EXPECT_EQ(service->UpdateAuthenticationResult(contextId, scheduleResult, authResultInfo,
        enrolledState), RESULT_GENERAL_ERROR);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateAuthenticationResult_004, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    HdiGlobalConfigParam param = {};
    param.type = ENABLE_STATUS;
    param.value.enableStatus = true;
    param.authTypes.push_back(1);
    EXPECT_EQ(service->SetGlobalConfigParam(param), RESULT_SUCCESS);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 1;

    std::vector<CredentialInfo> deletedCredInfos;
    service->EnforceDeleteUser(userId, deletedCredInfos);

    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    AuthResultTest authResultTest = {};
    DoOnceAuth(service, userId, authType, challenge, authResultTest);
    EXPECT_EQ(authResultTest.result, 0);

    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestCancelAuthentication_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t contextId = 256487;
    EXPECT_EQ(service->CancelAuthentication(contextId), 10006);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestCancelAuthentication_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 2;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    constexpr uint64_t contextId = 653497;
    AuthParam authParam = {};
    authParam.baseParam.userId = userId;
    authParam.baseParam.authTrustLevel = ATL1;
    authParam.authType = authType;
    authParam.baseParam.challenge = challenge;
    std::vector<ScheduleInfo> scheduleInfos;
    EXPECT_EQ(service->BeginAuthentication(contextId, authParam, scheduleInfos), 0);
    EXPECT_TRUE(!scheduleInfos.empty());

    EXPECT_EQ(service->CancelAuthentication(contextId), 0);

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginIdentification_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t contextId = 123456;
    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> challenge;
    uint32_t executorSensorHint = 0;
    ScheduleInfo scheduleInfo = {};

    EXPECT_EQ(service->BeginIdentification(contextId, authType, challenge, executorSensorHint, scheduleInfo), 8);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginIdentification_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t contextId = 623159;
    AuthType authType = AuthType::FACE;
    std::vector<uint8_t> challenge;
    uint32_t executorSensorHint = 0;
    ScheduleInfo scheduleInfo = {};

    EXPECT_EQ(service->BeginIdentification(contextId, authType, challenge, executorSensorHint, scheduleInfo), 2);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestBeginIdentification_003, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    ExecutorRegisterInfo info = {};
    info.authType = AuthType::FACE;
    info.executorRole = ExecutorRole::ALL_IN_ONE;
    info.esl = ExecutorSecureLevel::ESL0;
    EXPECT_EQ(GetExecutorPublicKey(info.publicKey), 0);
    uint64_t index = 0;
    std::vector<uint8_t> publicKey;
    std::vector<uint64_t> templateIds;
    EXPECT_EQ(service->AddExecutor(info, index, publicKey, templateIds), 0);

    constexpr uint64_t contextId = 623159;
    AuthType authType = AuthType::FACE;
    std::vector<uint8_t> challenge;
    uint32_t executorSensorHint = 0;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginIdentification(contextId, authType, challenge, executorSensorHint, scheduleInfo), 0);

    EXPECT_EQ(service->DeleteExecutor(index), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateIdentificationResult_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t contextId = 621327;
    std::vector<uint8_t> scheduleResult;
    IdentifyResultInfo identityResultInfo = {};
    EXPECT_EQ(service->UpdateIdentificationResult(contextId, scheduleResult, identityResultInfo), 8);

    scheduleResult.resize(240);
    EXPECT_EQ(service->UpdateIdentificationResult(contextId, scheduleResult, identityResultInfo),
        RESULT_GENERAL_ERROR);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdateIdentificationResult_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 3;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    EnrollResultTest enrollPinResultTest = {};
    std::vector<uint8_t> authToken;
    DoOnceEnroll(service, userId, AuthType::PIN, authToken, enrollPinResultTest);
    EXPECT_EQ(enrollPinResultTest.result, 0);

    AuthResultTest authResultTest = {};
    DoOnceAuth(service, userId, AuthType::PIN, challenge, authResultTest);
    EXPECT_EQ(authResultTest.result, 0);

    EnrollResultTest enrollFaceResultTest = {};
    DoOnceEnroll(service, userId, AuthType::FACE, authResultTest.token, enrollFaceResultTest);
    EXPECT_EQ(enrollFaceResultTest.result, 0);

    constexpr uint64_t contextId = 623159;
    AuthType authType = AuthType::FACE;
    uint32_t executorSensorHint = 0;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginIdentification(contextId, authType, challenge, executorSensorHint, scheduleInfo), 0);

    std::vector<uint8_t> identityScheduleResult;
    TlvRequiredPara para = {};
    para.result = 0;
    para.scheduleId = scheduleInfo.scheduleId;
    para.subType = 10000;
    para.templateId = 20;
    para.remainAttempts = 5;
    EXPECT_EQ(GetExecutorResultTlv(para, identityScheduleResult), 0);
    IdentifyResultInfo identityResultInfo = {};
    EXPECT_EQ(service->UpdateIdentificationResult(contextId, identityScheduleResult, identityResultInfo), 0);

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestCancelIdentification_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t contextId = 653215;
    EXPECT_EQ(service->CancelIdentification(contextId), 10006);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestCancelIdentification_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 4;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    EnrollResultTest enrollPinResultTest = {};
    std::vector<uint8_t> authToken;
    DoOnceEnroll(service, userId, AuthType::PIN, authToken, enrollPinResultTest);
    EXPECT_EQ(enrollPinResultTest.result, 0);

    AuthResultTest authResultTest = {};
    DoOnceAuth(service, userId, AuthType::PIN, challenge, authResultTest);
    EXPECT_EQ(authResultTest.result, 0);

    EnrollResultTest enrollFaceResultTest = {};
    DoOnceEnroll(service, userId, AuthType::FACE, authResultTest.token, enrollFaceResultTest);
    EXPECT_EQ(enrollFaceResultTest.result, 0);

    constexpr uint64_t contextId = 623159;
    AuthType authType = AuthType::FACE;
    uint32_t executorSensorHint = 0;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginIdentification(contextId, authType, challenge, executorSensorHint, scheduleInfo), 0);

    EXPECT_EQ(service->CancelIdentification(contextId), 0);

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestGetCredential_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 635648;
    AuthType authType = AuthType::PIN;
    std::vector<CredentialInfo> credInfos;

    EXPECT_EQ(service->GetCredential(userId, authType, credInfos), 0);
    EXPECT_TRUE(credInfos.empty());
}

HWTEST_F(UserAuthInterfaceServiceTest, TestGetCredential_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 635648;
    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    std::vector<CredentialInfo> credInfos;
    EXPECT_EQ(service->GetCredential(userId, authType, credInfos), 0);
    EXPECT_TRUE(!credInfos.empty());

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestGetUserInfo_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 635648;
    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    uint64_t secureUid = 0;
    int32_t subType = PinSubType::PIN_SIX;
    std::vector<EnrolledInfo> enrolledInfos;
    EXPECT_EQ(service->GetUserInfo(userId, secureUid, subType, enrolledInfos), 0);
    EXPECT_TRUE(!enrolledInfos.empty());

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestDeleteUser_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 321657;
    std::vector<uint8_t> authToken;
    std::vector<CredentialInfo> deletedCredInfos;
    std::vector<uint8_t> rootSecret;
    EXPECT_EQ(service->DeleteUser(userId, authToken, deletedCredInfos, rootSecret), RESULT_VERIFY_TOKEN_FAIL);

    authToken.resize(sizeof(UserAuthTokenHal));
    EXPECT_EQ(service->DeleteUser(userId, authToken, deletedCredInfos, rootSecret), 10017);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestDeleteUser_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 321657;
    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    AuthResultTest authResultTest = {};
    DoOnceAuth(service, userId, authType, challenge, authResultTest);
    EXPECT_EQ(authResultTest.result, 0);

    std::vector<CredentialInfo> deletedCredInfos;
    std::vector<uint8_t> rootSecret;
    EXPECT_EQ(service->DeleteUser(userId, authResultTest.token, deletedCredInfos, rootSecret), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestEnforceDeleteUser_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 635678;
    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 10006);
    EXPECT_TRUE(deletedCredInfos.empty());
}

HWTEST_F(UserAuthInterfaceServiceTest, TestEnforceDeleteUser_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 635678;
    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestGetAvailableStatus_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 325614;
    AuthType authType = AuthType::PIN;
    uint32_t authTrustLevel = 0;
    int32_t checkRet;
    EXPECT_EQ(service->GetAvailableStatus(userId, authType, authTrustLevel, checkRet), RESULT_SUCCESS);
    EXPECT_EQ(checkRet, RESULT_TYPE_NOT_SUPPORT);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestGetAvailableStatus_002, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 325614;
    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    uint32_t authTrustLevel = 0;
    int32_t checkRet;
    EXPECT_EQ(service->GetAvailableStatus(userId, authType, authTrustLevel, checkRet), 0);

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestUpdatePin, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 325678;
    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    AuthResultTest authResultTest = {};
    DoOnceAuth(service, userId, authType, challenge, authResultTest);
    EXPECT_EQ(authResultTest.result, 0);

    DoOnceEnroll(service, userId, authType, authResultTest.token, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestEnrollTwice, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 363156;
    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    EnrollParam enrollParam = {};
    enrollParam.userId = userId;
    enrollParam.authType = authType;
    ScheduleInfo scheduleInfo = {};
    EXPECT_EQ(service->BeginEnrollment(authToken, enrollParam, scheduleInfo), 10018);

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestInitTwice, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 368635;
    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    EXPECT_EQ(service->Init(deviceUdid), 0);

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestAuthLock, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr int32_t userId = 365861;
    AuthType authType = AuthType::PIN;
    std::vector<uint8_t> challenge;
    EXPECT_EQ(service->OpenSession(userId, challenge), 0);

    RegisterAllExecutor(service);

    std::vector<uint8_t> authToken;
    EnrollResultTest enrollResultTest = {};
    DoOnceEnroll(service, userId, authType, authToken, enrollResultTest);
    EXPECT_EQ(enrollResultTest.result, 0);

    constexpr uint64_t contextId = 636548;
    AuthParam authParam = {};
    authParam.baseParam.userId = userId;
    authParam.baseParam.authTrustLevel = ATL1;
    authParam.authType = authType;
    authParam.baseParam.challenge = challenge;
    std::vector<ScheduleInfo> scheduleInfos;
    EXPECT_EQ(service->BeginAuthentication(contextId, authParam, scheduleInfos), 0);
    EXPECT_TRUE(!scheduleInfos.empty());

    std::vector<uint8_t> authScheduleResult;
    TlvRequiredPara para = {};
    para.result = 2;
    para.scheduleId = scheduleInfos[0].scheduleId;
    para.subType = 10000;
    para.templateId = 20;
    para.remainAttempts = 0;
    EXPECT_EQ(GetExecutorResultTlv(para, authScheduleResult), 0);
    AuthResultInfo authResultInfo = {};
    EnrolledState enrolledState = {};

    EXPECT_EQ(service->UpdateAuthenticationResult(contextId, authScheduleResult, authResultInfo, enrolledState),
        RESULT_SUCCESS);

    std::vector<CredentialInfo> deletedCredInfos;
    EXPECT_EQ(service->EnforceDeleteUser(userId, deletedCredInfos), 0);
    EXPECT_TRUE(!deletedCredInfos.empty());

    DeleteAllExecutor(service);
    EXPECT_EQ(service->CloseSession(userId), 0);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestCheckReuseUnlockResult_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    ReuseUnlockParam param;
    ReuseUnlockInfo info;
    param.baseParam.userId = 1;
    EXPECT_EQ(service->CheckReuseUnlockResult(param, info), RESULT_BAD_PARAM);

    param.authTypes.push_back(static_cast<AuthType>(PIN));
    param.authTypes.push_back(static_cast<AuthType>(FACE));
    param.authTypes.push_back(static_cast<AuthType>(FINGERPRINT));
    param.authTypes.push_back(static_cast<AuthType>(0));
    EXPECT_EQ(service->CheckReuseUnlockResult(param, info), RESULT_BAD_PARAM);
    param.authTypes.pop_back();
    param.reuseUnlockResultDuration = 0;
    EXPECT_EQ(service->CheckReuseUnlockResult(param, info), RESULT_BAD_PARAM);
    param.reuseUnlockResultDuration = 6 * 60 *1000;
    EXPECT_EQ(service->CheckReuseUnlockResult(param, info), RESULT_BAD_PARAM);
    param.reuseUnlockResultDuration = 5 * 60 *1000;
    EXPECT_EQ(service->CheckReuseUnlockResult(param, info), RESULT_BAD_PARAM);
    param.reuseUnlockResultMode = 0;
    EXPECT_EQ(service->CheckReuseUnlockResult(param, info), RESULT_BAD_PARAM);
    param.reuseUnlockResultMode = 1;
    EXPECT_EQ(service->CheckReuseUnlockResult(param, info), RESULT_GENERAL_ERROR);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestSetGlobalConfigParam_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    HdiGlobalConfigParam param = {};
    param.type = 0;
    param.value.pinExpiredPeriod = 0;
    EXPECT_EQ(service->SetGlobalConfigParam(param), RESULT_BAD_PARAM);

    param.type = PIN_EXPIRED_PERIOD;
    EXPECT_EQ(service->SetGlobalConfigParam(param), RESULT_BAD_PARAM);
    param.authTypes.push_back(1);
    EXPECT_EQ(service->SetGlobalConfigParam(param), RESULT_SUCCESS);
    param.value.pinExpiredPeriod = 1;
    EXPECT_EQ(service->SetGlobalConfigParam(param), RESULT_SUCCESS);

    param.authTypes.clear();
    param.type = ENABLE_STATUS;
    param.value.enableStatus = true;
    EXPECT_EQ(service->SetGlobalConfigParam(param), RESULT_BAD_PARAM);
    param.authTypes.push_back(1);
    EXPECT_EQ(service->SetGlobalConfigParam(param), RESULT_SUCCESS);
    param.authTypes.push_back(2);
    param.authTypes.push_back(4);
    param.authTypes.push_back(4);
    param.authTypes.push_back(8);
    param.authTypes.push_back(16);
    EXPECT_EQ(service->SetGlobalConfigParam(param), RESULT_BAD_PARAM);

    for (uint32_t i = 0; i <= MAX_USER; i++) {
        param.userIds.push_back(i);
    }
    EXPECT_EQ(service->SetGlobalConfigParam(param), RESULT_BAD_PARAM);

    param.authTypes.clear();
    param.userIds.clear();
    param.type = PIN_EXPIRED_PERIOD;
    param.authTypes.push_back(1);
    param.value.pinExpiredPeriod = NO_CHECK_PIN_EXPIRED_PERIOD;
    EXPECT_EQ(service->SetGlobalConfigParam(param), RESULT_SUCCESS);
}

HWTEST_F(UserAuthInterfaceServiceTest, TestVerifyAuthToken_001, TestSize.Level0)
{
    auto service = UserIam::Common::MakeShared<UserAuthInterfaceService>();
    EXPECT_NE(service, nullptr);

    const std::string deviceUdid = std::string(64, ' ');
    EXPECT_EQ(service->Init(deviceUdid), 0);

    constexpr uint64_t allowableDuration = 1000;
    std::vector<uint8_t> tokenIn = {};
    HdiUserAuthTokenPlain tokenPlainOut = {};
    std::vector<uint8_t> rootSecret = {};
    EXPECT_EQ(service->VerifyAuthToken(tokenIn, allowableDuration, tokenPlainOut, rootSecret),
        RESULT_BAD_PARAM);
    tokenIn.resize(sizeof(UserAuthTokenHal));
    EXPECT_EQ(service->VerifyAuthToken(tokenIn, allowableDuration, tokenPlainOut, rootSecret),
        INNER_RESULT_AUTH_TOKEN_EXPIRED);
}
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS