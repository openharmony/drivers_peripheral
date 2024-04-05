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

#include <gtest/gtest.h>

#include "idm_database.h"

typedef bool (*DuplicateCheckFunc)(LinkedList *collection, uint64_t value);

extern "C" {
    extern LinkedList *g_userInfoList;
    extern UserInfo *g_currentUser;
    extern bool MatchUserInfo(const void *data, const void *condition);
    extern bool IsUserInfoValid(UserInfo *userInfo);
    extern UserInfo *QueryUserInfo(int32_t userId);
    extern bool IsSecureUidDuplicate(LinkedList *userInfoList, uint64_t secureUid);
    extern UserInfo *CreateUser(int32_t userId);
    extern ResultCode DeleteUser(int32_t userId);
    extern bool IsCredentialIdDuplicate(LinkedList *userInfoList, uint64_t credentialId);
    extern bool IsEnrolledIdDuplicate(LinkedList *enrolledList, uint64_t enrolledId);
    extern ResultCode GenerateDeduplicateUint64(LinkedList *collection, uint64_t *destValue, DuplicateCheckFunc func);
    extern ResultCode UpdateEnrolledId(LinkedList *enrolledList, uint32_t authType);
    extern ResultCode AddCredentialToUser(UserInfo *user, CredentialInfoHal *credentialInfo);
    extern ResultCode AddUser(int32_t userId, CredentialInfoHal *credentialInfo);
    extern bool MatchCredentialById(const void *data, const void *condition);
    extern bool MatchEnrolledInfoByType(const void *data, const void *condition);
    extern CredentialInfoHal *QueryCredentialById(uint64_t credentialId, LinkedList *credentialList);
    extern CredentialInfoHal *QueryCredentialByAuthType(uint32_t authType, LinkedList *credentialList);
    extern bool IsCredMatch(const CredentialCondition *limit, const CredentialInfoHal *credentialInfo);
    extern bool IsUserMatch(const CredentialCondition *limit, const UserInfo *user);
    extern ResultCode TraverseCredentialList(const CredentialCondition *limit, const LinkedList *credentialList,
        LinkedList *credListGet);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class IdmDatabaseTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(IdmDatabaseTest, TestInitUserInfoList, TestSize.Level0)
{
    EXPECT_EQ(InitUserInfoList(), RESULT_SUCCESS);
    DestroyUserInfoList();
}

HWTEST_F(IdmDatabaseTest, TestMatchUserInfo, TestSize.Level0)
{
    EXPECT_FALSE(MatchUserInfo(nullptr, nullptr));
    int32_t condition = 4526;
    constexpr int32_t USER_ID = 1133;
    UserInfo info = {};
    info.userId = USER_ID;
    EXPECT_FALSE(MatchUserInfo(static_cast<void *>(&info), static_cast<void *>(&condition)));
}

HWTEST_F(IdmDatabaseTest, TestIsUserInfoValid, TestSize.Level0)
{
    UserInfo info = {};
    info.credentialInfoList = nullptr;
    info.enrolledInfoList = nullptr;
    EXPECT_FALSE(IsUserInfoValid(&info));
    info.credentialInfoList = new LinkedList();
    EXPECT_FALSE(IsUserInfoValid(&info));
    delete info.credentialInfoList;
}

HWTEST_F(IdmDatabaseTest, TestGetSecureUid, TestSize.Level0)
{
    constexpr int32_t USER_ID = 1133;
    EXPECT_EQ(GetSecureUid(USER_ID, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfoAuthType_001, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr int32_t USER_ID = 1166;
    constexpr uint32_t AUTH_TYPE = 1;
    EXPECT_EQ(GetEnrolledInfoAuthType(USER_ID, AUTH_TYPE, nullptr), RESULT_BAD_PARAM);
    EnrolledInfoHal info = {};
    EXPECT_EQ(GetEnrolledInfoAuthType(USER_ID, AUTH_TYPE, &info), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfoAuthType_002, TestSize.Level0)
{
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    constexpr int32_t USER_ID = 1135;
    constexpr uint32_t AUTH_TYPE = 1;
    userInfo.userId = USER_ID;
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    EnrolledInfoHal info = {};
    EXPECT_EQ(GetEnrolledInfoAuthType(USER_ID, AUTH_TYPE, &info), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfoAuthType_003, TestSize.Level0)
{
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    constexpr int32_t USER_ID = 1135;
    constexpr uint32_t AUTH_TYPE_1 = 1;
    constexpr uint32_t AUTH_TYPE_2 = 2;
    userInfo.userId = USER_ID;
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EnrolledInfoHal enrolledInfo = {};
    enrolledInfo.authType = AUTH_TYPE_2;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    g_userInfoList->insert(g_userInfoList, nullptr);
    EnrolledInfoHal info = {};
    EXPECT_EQ(GetEnrolledInfoAuthType(USER_ID, AUTH_TYPE_1, &info), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfo, TestSize.Level0)
{
    constexpr int32_t USER_ID = 1211;
    EXPECT_EQ(GetEnrolledInfo(USER_ID, nullptr, nullptr), RESULT_BAD_PARAM);
    g_userInfoList = nullptr;
    g_currentUser = nullptr;
    EnrolledInfoHal *enrolledInfos = nullptr;
    uint32_t num = 0;
    EXPECT_EQ(GetEnrolledInfo(USER_ID, &enrolledInfos, &num), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestDeleteUserInfo, TestSize.Level0)
{
    constexpr int32_t USER_ID = 1155;
    EXPECT_EQ(DeleteUserInfo(USER_ID, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestQueryUserInfo_001, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr int32_t USER_ID_1 = 123;
    constexpr int32_t USER_ID_2 = 1123;
    UserInfo userInfo = {};
    userInfo.userId = USER_ID_1;
    g_currentUser = &userInfo;
    EXPECT_NE(QueryUserInfo(USER_ID_1), nullptr);
    userInfo.userId = USER_ID_2;
    EXPECT_EQ(QueryUserInfo(USER_ID_1), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestQueryUserInfo_002, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    constexpr int32_t USER_ID_1 = 123;
    constexpr int32_t USER_ID_2 = 1336;
    UserInfo userInfo1 = {};
    userInfo1.userId = USER_ID_1;
    userInfo1.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo1.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo1));
    UserInfo userInfo2 = {};
    userInfo2.userId = USER_ID_2;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo2));
    g_userInfoList->insert(g_userInfoList, nullptr);
    EXPECT_NE(QueryUserInfo(USER_ID_1), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestIsSecureUidDuplicate, TestSize.Level0)
{
    constexpr uint64_t SEC_UID = 1221;
    constexpr uint64_t SEC_UID_1 = 111;
    constexpr uint64_t SEC_UID_2 = 222;
    EXPECT_FALSE(IsSecureUidDuplicate(nullptr, SEC_UID));
    LinkedList *userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(userInfoList, nullptr);
    EXPECT_FALSE(IsSecureUidDuplicate(userInfoList, SEC_UID));
    UserInfo info1 = {};
    info1.secUid = SEC_UID_1;
    userInfoList->insert(userInfoList, static_cast<void *>(&info1));
    UserInfo info2 = info1;
    info2.secUid = SEC_UID_2;
    userInfoList->insert(userInfoList, static_cast<void *>(&info2));
    userInfoList->insert(userInfoList, nullptr);
    EXPECT_TRUE(IsSecureUidDuplicate(userInfoList, SEC_UID_1));
}

HWTEST_F(IdmDatabaseTest, TestCreateUser, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr int32_t USER_ID = 123;
    EXPECT_EQ(CreateUser(USER_ID), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestDeleteUser, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr int32_t USER_ID = 123;
    EXPECT_EQ(DeleteUser(USER_ID), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestIsCredentialIdDuplicate, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr uint64_t CREDENTIAL_ID_1 = 1221;
    constexpr uint64_t CREDENTIAL_ID_2 = 10;
    EXPECT_TRUE(IsCredentialIdDuplicate(nullptr, CREDENTIAL_ID_1));
    g_userInfoList =  CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo info = {};
    info.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(info.credentialInfoList, nullptr);
    CredentialInfoHal credInfo = {};
    credInfo.credentialId = CREDENTIAL_ID_2;
    info.credentialInfoList->insert(info.credentialInfoList, static_cast<void *>(&credInfo));
    g_userInfoList->insert(g_userInfoList, &info);
    EXPECT_TRUE(IsCredentialIdDuplicate(nullptr, CREDENTIAL_ID_2));
}

HWTEST_F(IdmDatabaseTest, TestIsEnrolledIdDuplicate, TestSize.Level0)
{
    constexpr uint64_t ENROLLED_ID_1 = 111;
    constexpr uint64_t ENROLLED_ID_2 = 222;
    LinkedList *enrolledList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(enrolledList, nullptr);
    EnrolledInfoHal info1 = {};
    info1.enrolledId = ENROLLED_ID_1;
    enrolledList->insert(enrolledList, static_cast<void *>(&info1));
    EnrolledInfoHal info2 = {};
    info2.enrolledId = ENROLLED_ID_2;
    enrolledList->insert(enrolledList, static_cast<void *>(&info2));
    enrolledList->insert(enrolledList, nullptr);
    EXPECT_TRUE(IsEnrolledIdDuplicate(enrolledList, ENROLLED_ID_1));
}

HWTEST_F(IdmDatabaseTest, TestGenerateDeduplicateUint64, TestSize.Level0)
{
    EXPECT_EQ(GenerateDeduplicateUint64(nullptr, nullptr, IsEnrolledIdDuplicate), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestUpdateEnrolledId, TestSize.Level0)
{
    constexpr uint32_t AUTH_TYPE_1 = 1;
    constexpr uint32_t AUTH_TYPE_2 = 2;
    LinkedList *enrolledList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(enrolledList, nullptr);
    EnrolledInfoHal info1 = {};
    info1.authType = AUTH_TYPE_1;
    enrolledList->insert(enrolledList, static_cast<void *>(&info1));
    EnrolledInfoHal info2 = {};
    info2.authType = AUTH_TYPE_2;
    enrolledList->insert(enrolledList, static_cast<void *>(&info2));
    enrolledList->insert(enrolledList, nullptr);
    EXPECT_EQ(UpdateEnrolledId(enrolledList, AUTH_TYPE_1), RESULT_SUCCESS);
}

HWTEST_F(IdmDatabaseTest, TestAddCredentialToUser, TestSize.Level0)
{
    g_userInfoList = nullptr;
    EXPECT_EQ(AddCredentialToUser(nullptr, nullptr), RESULT_NEED_INIT);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    UserInfo userInfo = {};
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    CredentialInfoHal credInfo = {};
    constexpr uint32_t CRED_NUM = 102;
    for (uint32_t i = 0; i < CRED_NUM; ++i) {
        userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credInfo));
    }
    EXPECT_EQ(AddCredentialToUser(&userInfo, nullptr), RESULT_EXCEED_LIMIT);
}

HWTEST_F(IdmDatabaseTest, TestAddUser, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = nullptr;
    EXPECT_EQ(AddUser(111, nullptr), RESULT_NEED_INIT);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    constexpr uint32_t USER_NUM = 1002;
    UserInfo info = {};
    for (uint32_t i = 0; i < USER_NUM; ++i) {
        g_userInfoList->insert(g_userInfoList, static_cast<void *>(&info));
    }
    EXPECT_EQ(AddUser(111, nullptr), RESULT_EXCEED_LIMIT);
}

HWTEST_F(IdmDatabaseTest, TestAddCredentialInfo, TestSize.Level0)
{
    EXPECT_EQ(AddCredentialInfo(111, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestMatchCredentialById, TestSize.Level0)
{
    EXPECT_FALSE(MatchCredentialById(nullptr, nullptr));
    constexpr uint64_t CREDENTIAL_ID = 10;
    CredentialInfoHal info = {};
    info.credentialId = CREDENTIAL_ID;
    uint64_t condition = CREDENTIAL_ID;
    EXPECT_TRUE(MatchCredentialById(static_cast<void *>(&info), static_cast<void *>(&condition)));
    condition = 20;
    EXPECT_FALSE(MatchCredentialById(static_cast<void *>(&info), static_cast<void *>(&condition)));
}

HWTEST_F(IdmDatabaseTest, TestMatchEnrolledInfoByType, TestSize.Level0)
{
    EXPECT_FALSE(MatchEnrolledInfoByType(nullptr, nullptr));
    constexpr uint32_t AUTH_TYPE = 1;
    EnrolledInfoHal info = {};
    info.authType = AUTH_TYPE;
    uint32_t condition = 1;
    EXPECT_TRUE(MatchEnrolledInfoByType(static_cast<void *>(&info), static_cast<void *>(&condition)));
    condition = 2;
    EXPECT_FALSE(MatchEnrolledInfoByType(static_cast<void *>(&info), static_cast<void *>(&condition)));
}

HWTEST_F(IdmDatabaseTest, TestDeleteCredentialInfo_001, TestSize.Level0)
{
    EXPECT_EQ(DeleteCredentialInfo(1, 1, nullptr), RESULT_BAD_PARAM);
    CredentialInfoHal credInfo = {};
    EXPECT_EQ(DeleteCredentialInfo(1, 1, &credInfo), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestDeleteCredentialInfo_002, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    constexpr int32_t USER_ID = 112;
    constexpr uint64_t CREDENTIAL_ID = 1;
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = USER_ID;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    CredentialInfoHal credInfo = {};
    EXPECT_EQ(DeleteCredentialInfo(USER_ID, CREDENTIAL_ID, &credInfo), RESULT_UNKNOWN);
}

HWTEST_F(IdmDatabaseTest, TestDeleteCredentialInfo_003, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    constexpr int32_t USER_ID = 113;
    constexpr uint64_t CREDENTIAL_ID = 10;
    UserInfo userInfo = {};
    userInfo.userId = USER_ID;
    userInfo.enrolledInfoList = nullptr;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    auto *credInfo = static_cast<CredentialInfoHal *>(Malloc(sizeof(CredentialInfoHal)));
    credInfo->credentialId = CREDENTIAL_ID;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(credInfo));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    CredentialInfoHal info = {};
    EXPECT_EQ(DeleteCredentialInfo(USER_ID, CREDENTIAL_ID, &info), 10006);
}

HWTEST_F(IdmDatabaseTest, TestDeleteCredentialInfo_004, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    constexpr int32_t USER_ID = 115;
    constexpr uint32_t AUTH_TYPE = 2;
    constexpr uint64_t CREDENTIAL_ID_1 = 10;
    constexpr uint64_t CREDENTIAL_ID_2 = 20;
    UserInfo userInfo = {};
    userInfo.userId = USER_ID;
    userInfo.enrolledInfoList = nullptr;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    auto *credInfo1 = static_cast<CredentialInfoHal *>(Malloc(sizeof(CredentialInfoHal)));
    credInfo1->credentialId = CREDENTIAL_ID_1;
    credInfo1->authType = AUTH_TYPE;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(credInfo1));
    auto *credInfo2 = static_cast<CredentialInfoHal *>(Malloc(sizeof(CredentialInfoHal)));
    credInfo2->credentialId = CREDENTIAL_ID_2;
    credInfo2->authType = AUTH_TYPE;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(credInfo2));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    CredentialInfoHal info = {};
    EXPECT_EQ(DeleteCredentialInfo(USER_ID, CREDENTIAL_ID_1, &info), RESULT_SUCCESS);
    Free(credInfo2);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialById, TestSize.Level0)
{
    constexpr uint64_t CREDENTIAL_ID = 111;
    constexpr uint64_t CREDENTIAL_ID_1 = 10;
    constexpr uint64_t CREDENTIAL_ID_2 = 20;
    EXPECT_EQ(QueryCredentialById(CREDENTIAL_ID, nullptr), nullptr);
    LinkedList *credentialList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(credentialList, nullptr);
    CredentialInfoHal credInfo1 = {};
    credInfo1.credentialId = CREDENTIAL_ID_1;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo1));
    CredentialInfoHal credInfo2 = {};
    credInfo2.credentialId = CREDENTIAL_ID_2;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo2));
    credentialList->insert(credentialList, nullptr);
    EXPECT_NE(QueryCredentialById(CREDENTIAL_ID_1, credentialList), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialByAuthType, TestSize.Level0)
{
    constexpr uint32_t AUTH_TYPE_1 = 1;
    constexpr uint32_t AUTH_TYPE_2 = 2;
    EXPECT_EQ(QueryCredentialByAuthType(1, nullptr), nullptr);
    LinkedList *credentialList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(credentialList, nullptr);
    CredentialInfoHal credInfo1 = {};
    credInfo1.authType = AUTH_TYPE_1;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo1));
    CredentialInfoHal credInfo2 = {};
    credInfo2.authType = AUTH_TYPE_2;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo2));
    credentialList->insert(credentialList, nullptr);
    EXPECT_NE(QueryCredentialByAuthType(AUTH_TYPE_1, credentialList), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestIsCredMatch_001, TestSize.Level0)
{
    constexpr uint64_t TEMPLATE_ID_1 = 20;
    constexpr uint64_t TEMPLATE_ID_2 = 10;
    CredentialInfoHal credInfo = {};
    credInfo.templateId = TEMPLATE_ID_1;
    CredentialCondition limit = {};
    SetCredentialConditionTemplateId(&limit, TEMPLATE_ID_2);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
}

HWTEST_F(IdmDatabaseTest, TestIsCredMatch_002, TestSize.Level0)
{
    constexpr uint32_t EXCUTOR_SENSOR_HINT_1 = 10;
    constexpr uint32_t EXCUTOR_SENSOR_HINT_2 = 20;
    CredentialInfoHal credInfo = {};
    credInfo.executorSensorHint = EXCUTOR_SENSOR_HINT_2;
    CredentialCondition limit = {};
    SetCredentialConditionExecutorSensorHint(&limit, 0);
    EXPECT_TRUE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorSensorHint(&limit, EXCUTOR_SENSOR_HINT_1);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorSensorHint(&limit, EXCUTOR_SENSOR_HINT_2);
    EXPECT_TRUE(IsCredMatch(&limit, &credInfo));
}

HWTEST_F(IdmDatabaseTest, TestIsCredMatch_003, TestSize.Level0)
{
    constexpr uint32_t EXCUTOR_MATCHER_1 = 10;
    constexpr uint32_t EXCUTOR_MATCHER_2 = 20;
    CredentialInfoHal credInfo = {};
    credInfo.executorMatcher = EXCUTOR_MATCHER_2;
    CredentialCondition limit = {};
    EXPECT_TRUE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorMatcher(&limit, EXCUTOR_MATCHER_1);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorMatcher(&limit, EXCUTOR_MATCHER_2);
    EXPECT_TRUE(IsCredMatch(&limit, &credInfo));
}

HWTEST_F(IdmDatabaseTest, TestIsUserMatch, TestSize.Level0)
{
    constexpr int32_t USER_ID_1 = 20;
    constexpr int32_t USER_ID_2 = 10;
    UserInfo userInfo = {};
    userInfo.userId = USER_ID_1;
    CredentialCondition limit = {};
    SetCredentialConditionUserId(&limit, USER_ID_2);
    EXPECT_FALSE(IsUserMatch(&limit, &userInfo));
}

HWTEST_F(IdmDatabaseTest, TestTraverseCredentialList, TestSize.Level0)
{
    EXPECT_EQ(TraverseCredentialList(nullptr, nullptr, nullptr), RESULT_GENERAL_ERROR);
    LinkedList *credentialList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(credentialList, nullptr);
    credentialList->insert(credentialList, nullptr);
    EXPECT_EQ(TraverseCredentialList(nullptr, credentialList, nullptr), RESULT_UNKNOWN);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialLimit_001, TestSize.Level0)
{
    g_userInfoList = nullptr;
    EXPECT_EQ(QueryCredentialLimit(nullptr), nullptr);
    CredentialCondition limit = {};
    EXPECT_EQ(QueryCredentialLimit(&limit), nullptr);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    g_userInfoList->insert(g_userInfoList, nullptr);
    EXPECT_EQ(QueryCredentialLimit(&limit), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialLimit_002, TestSize.Level0)
{
    constexpr int32_t USER_ID_1 = 1001;
    constexpr int32_t USER_ID_2 = 1002;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo1 = {};
    userInfo1.userId = USER_ID_1;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo1));
    UserInfo userInfo2 = {};
    userInfo2.userId = USER_ID_2;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo2));
    CredentialCondition limit = {};
    SetCredentialConditionUserId(&limit, USER_ID_1);
    EXPECT_EQ(QueryCredentialLimit(&limit), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialUserId_001, TestSize.Level0)
{
    constexpr int32_t USER_ID = 1001;
    constexpr uint64_t CREDENTIAL_ID = 10;
    g_userInfoList = nullptr;
    EXPECT_EQ(QueryCredentialUserId(CREDENTIAL_ID, nullptr), RESULT_BAD_PARAM);
    int32_t userId = USER_ID;
    EXPECT_EQ(QueryCredentialUserId(CREDENTIAL_ID, &userId), RESULT_NEED_INIT);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    EXPECT_EQ(QueryCredentialUserId(CREDENTIAL_ID, &userId), RESULT_NOT_FOUND);
    g_userInfoList->insert(g_userInfoList, nullptr);
    EXPECT_EQ(QueryCredentialUserId(CREDENTIAL_ID, &userId), RESULT_UNKNOWN);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialUserId_002, TestSize.Level0)
{
    constexpr int32_t USER_ID_1 = 1002;
    constexpr int32_t USER_ID_2 = 1001;
    constexpr uint64_t CREDENTIAL_ID = 10;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = USER_ID_1;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    int32_t userId = USER_ID_2;
    EXPECT_EQ(QueryCredentialUserId(CREDENTIAL_ID, &userId), RESULT_UNKNOWN);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialUserId_003, TestSize.Level0)
{
    constexpr int32_t USER_ID_1 = 1002;
    constexpr int32_t USER_ID_2 = 1001;
    constexpr uint64_t CREDENTIAL_ID = 10;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = USER_ID_1;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    int32_t userId = USER_ID_2;
    EXPECT_EQ(QueryCredentialUserId(CREDENTIAL_ID, &userId), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestSetPinSubType, TestSize.Level0)
{
    g_userInfoList = nullptr;
    g_currentUser = nullptr;
    constexpr int32_t USER_ID = 1003;
    constexpr uint64_t PIN_SUB_TYPE = 10000;
    EXPECT_EQ(SetPinSubType(USER_ID, PIN_SUB_TYPE), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetPinSubType, TestSize.Level0)
{
    g_userInfoList = nullptr;
    g_currentUser = nullptr;
    constexpr int32_t USER_ID = 1005;
    constexpr uint64_t PIN_SUB_TYPE = 10000;
    EXPECT_EQ(GetPinSubType(USER_ID, nullptr), RESULT_BAD_PARAM);
    uint64_t subType = PIN_SUB_TYPE;
    EXPECT_EQ(GetPinSubType(USER_ID, &subType), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionCredentialId, TestSize.Level0)
{
    constexpr uint64_t CREDENTIAL_ID = 10;
    SetCredentialConditionCredentialId(nullptr, CREDENTIAL_ID);
    CredentialCondition condition = {};
    SetCredentialConditionCredentialId(&condition, CREDENTIAL_ID);
    EXPECT_EQ(condition.credentialId, CREDENTIAL_ID);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_CREDENTIAL_ID, CREDENTIAL_CONDITION_CREDENTIAL_ID);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionTemplateId, TestSize.Level0)
{
    constexpr uint64_t TEMPLATE_ID = 20;
    SetCredentialConditionTemplateId(nullptr, TEMPLATE_ID);
    CredentialCondition condition = {};
    SetCredentialConditionTemplateId(&condition, TEMPLATE_ID);
    EXPECT_EQ(condition.templateId, TEMPLATE_ID);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_TEMPLATE_ID, CREDENTIAL_CONDITION_TEMPLATE_ID);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionAuthType, TestSize.Level0)
{
    constexpr uint32_t AUTH_TYPE = 2;
    SetCredentialConditionAuthType(nullptr, AUTH_TYPE);
    CredentialCondition condition = {};
    SetCredentialConditionAuthType(&condition, AUTH_TYPE);
    EXPECT_EQ(condition.authType, AUTH_TYPE);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_AUTH_TYPE, CREDENTIAL_CONDITION_AUTH_TYPE);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionExecutorSensorHint, TestSize.Level0)
{
    constexpr uint32_t EXCUTOR_SENSOR_HINT = 20;
    SetCredentialConditionExecutorSensorHint(nullptr, EXCUTOR_SENSOR_HINT);
    CredentialCondition condition = {};
    SetCredentialConditionExecutorSensorHint(&condition, EXCUTOR_SENSOR_HINT);
    EXPECT_EQ(condition.executorSensorHint, EXCUTOR_SENSOR_HINT);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_SENSOR_HINT, CREDENTIAL_CONDITION_SENSOR_HINT);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionExecutorMatcher, TestSize.Level0)
{
    constexpr uint32_t EXCUTOR_MATCHER = 20;
    SetCredentialConditionExecutorMatcher(nullptr, EXCUTOR_MATCHER);
    CredentialCondition condition = {};
    SetCredentialConditionExecutorMatcher(&condition, EXCUTOR_MATCHER);
    EXPECT_EQ(condition.executorMatcher, EXCUTOR_MATCHER);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_EXECUTOR_MATCHER, CREDENTIAL_CONDITION_EXECUTOR_MATCHER);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionUserId, TestSize.Level0)
{
    constexpr int32_t USRE_ID = 50;
    SetCredentialConditionUserId(nullptr, USRE_ID);
    CredentialCondition condition = {};
    SetCredentialConditionUserId(&condition, USRE_ID);
    EXPECT_EQ(condition.userId, USRE_ID);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_USER_ID, CREDENTIAL_CONDITION_USER_ID);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledState_001, TestSize.Level0)
{
    constexpr int32_t USRE_ID = 1;
    constexpr uint32_t AUTH_TYPE = 1;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    UserInfo userInfo = {};
    userInfo.userId = USRE_ID;
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));

    EnrolledStateHal enrolledState = {};
    EXPECT_EQ(GetEnrolledState(0, AUTH_TYPE, &enrolledState), RESULT_NOT_ENROLLED);
    EXPECT_EQ(GetEnrolledState(USRE_ID, AUTH_TYPE, &enrolledState), RESULT_NOT_ENROLLED);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledState_002, TestSize.Level0)
{
    constexpr static int32_t EXPECT_CREDENTIAL_COUNT = 2;
    constexpr static int32_t TESR_ENROLLED_ID = 2;
    constexpr int32_t USRE_ID = 1;
    constexpr uint32_t AUTH_TYPE = 1;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);

    UserInfo userInfo = {};
    userInfo.userId = USRE_ID;
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    EnrolledInfoHal enrolledInfo = {1, TESR_ENROLLED_ID};
    userInfo.enrolledInfoList->insert(userInfo.enrolledInfoList, static_cast<void *>(&enrolledInfo));
    
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    CredentialInfoHal credentialInfo = {0, 0, 1, 0, 0, 0};
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credentialInfo));
    CredentialInfoHal credentialInfo1 = {1, 1, 1, 1, 1, 1};
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credentialInfo1));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));

    EnrolledStateHal enrolledState = {};
    EXPECT_EQ(GetEnrolledState(USRE_ID, AUTH_TYPE, &enrolledState), RESULT_SUCCESS);
    EXPECT_EQ(enrolledState.credentialDigest, TESR_ENROLLED_ID);
    EXPECT_EQ(enrolledState.credentialCount, EXPECT_CREDENTIAL_COUNT);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
