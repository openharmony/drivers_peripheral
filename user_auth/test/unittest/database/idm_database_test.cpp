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
    InitUserInfoList();
    InitUserInfoList();
    DestroyUserInfoList();
}

HWTEST_F(IdmDatabaseTest, TestMatchUserInfo, TestSize.Level0)
{
    EXPECT_FALSE(MatchUserInfo(nullptr, nullptr));
    int32_t condition = 4526;
    UserInfo info = {};
    info.userId = 1133;
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
    EXPECT_EQ(GetSecureUid(1133, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfoAuthType_001, TestSize.Level0)
{
    g_userInfoList = nullptr;
    EXPECT_EQ(GetEnrolledInfoAuthType(1166, 1, nullptr), RESULT_BAD_PARAM);
    EnrolledInfoHal info = {};
    EXPECT_EQ(GetEnrolledInfoAuthType(1166, 1, &info), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfoAuthType_002, TestSize.Level0)
{
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = 1135;
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    EnrolledInfoHal info = {};
    EXPECT_EQ(GetEnrolledInfoAuthType(1135, 1, &info), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfoAuthType_003, TestSize.Level0)
{
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = 1135;
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EnrolledInfoHal enrolledInfo = {};
    enrolledInfo.authType = 2;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    g_userInfoList->insert(g_userInfoList, nullptr);
    EnrolledInfoHal info = {};
    EXPECT_EQ(GetEnrolledInfoAuthType(1135, 1, &info), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfo, TestSize.Level0)
{
    EXPECT_EQ(GetEnrolledInfo(1211, nullptr, nullptr), RESULT_BAD_PARAM);
    g_userInfoList = nullptr;
    g_currentUser = nullptr;
    EnrolledInfoHal *enrolledInfos = nullptr;
    uint32_t num = 0;
    EXPECT_EQ(GetEnrolledInfo(1211, &enrolledInfos, &num), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestDeleteUserInfo, TestSize.Level0)
{
    EXPECT_EQ(DeleteUserInfo(1155, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestQueryUserInfo_001, TestSize.Level0)
{
    g_userInfoList = nullptr;
    UserInfo userInfo = {};
    userInfo.userId = 123;
    g_currentUser = &userInfo;
    EXPECT_NE(QueryUserInfo(123), nullptr);
    userInfo.userId = 1123;
    EXPECT_EQ(QueryUserInfo(123), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestQueryUserInfo_002, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo1 = {};
    userInfo1.userId = 123;
    userInfo1.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo1.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo1));
    UserInfo userInfo2 = {};
    userInfo2.userId = 1336;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo2));
    g_userInfoList->insert(g_userInfoList, nullptr);
    EXPECT_NE(QueryUserInfo(123), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestIsSecureUidDuplicate, TestSize.Level0)
{
    EXPECT_FALSE(IsSecureUidDuplicate(nullptr, 1221));
    LinkedList *userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(userInfoList, nullptr);
    EXPECT_FALSE(IsSecureUidDuplicate(userInfoList, 1221));
    UserInfo info1 = {};
    info1.secUid = 111;
    userInfoList->insert(userInfoList, static_cast<void *>(&info1));
    UserInfo info2 = info1;
    info2.secUid = 222;
    userInfoList->insert(userInfoList, static_cast<void *>(&info2));
    userInfoList->insert(userInfoList, nullptr);
    EXPECT_TRUE(IsSecureUidDuplicate(userInfoList, 111));
}

HWTEST_F(IdmDatabaseTest, TestCreateUser, TestSize.Level0)
{
    g_userInfoList = nullptr;
    EXPECT_EQ(CreateUser(123), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestDeleteUser, TestSize.Level0)
{
    g_userInfoList = nullptr;
    EXPECT_EQ(DeleteUser(123), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestIsCredentialIdDuplicate, TestSize.Level0)
{
    g_userInfoList = nullptr;
    EXPECT_TRUE(IsCredentialIdDuplicate(nullptr, 1221));
    g_userInfoList =  CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo info = {};
    info.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(info.credentialInfoList, nullptr);
    CredentialInfoHal credInfo = {};
    credInfo.credentialId = 10;
    info.credentialInfoList->insert(info.credentialInfoList, static_cast<void *>(&credInfo));
    g_userInfoList->insert(g_userInfoList, &info);
    EXPECT_TRUE(IsCredentialIdDuplicate(nullptr, 10));
}

HWTEST_F(IdmDatabaseTest, TestIsEnrolledIdDuplicate, TestSize.Level0)
{
    LinkedList *enrolledList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(enrolledList, nullptr);
    EnrolledInfoHal info1 = {};
    info1.enrolledId = 111;
    enrolledList->insert(enrolledList, static_cast<void *>(&info1));
    EnrolledInfoHal info2 = {};
    info2.enrolledId = 222;
    enrolledList->insert(enrolledList, static_cast<void *>(&info2));
    enrolledList->insert(enrolledList, nullptr);
    EXPECT_TRUE(IsEnrolledIdDuplicate(enrolledList, 111));
}

HWTEST_F(IdmDatabaseTest, TestGenerateDeduplicateUint64, TestSize.Level0)
{
    EXPECT_EQ(GenerateDeduplicateUint64(nullptr, nullptr, IsEnrolledIdDuplicate), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestUpdateEnrolledId, TestSize.Level0)
{
    LinkedList *enrolledList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(enrolledList, nullptr);
    EnrolledInfoHal info1 = {};
    info1.authType = 1;
    enrolledList->insert(enrolledList, static_cast<void *>(&info1));
    EnrolledInfoHal info2 = {};
    info2.authType = 2;
    enrolledList->insert(enrolledList, static_cast<void *>(&info2));
    enrolledList->insert(enrolledList, nullptr);
    EXPECT_EQ(UpdateEnrolledId(enrolledList, 1), RESULT_SUCCESS);
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
    uint32_t credNum = 102;
    for (uint32_t i = 0; i < credNum; ++i) {
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
    uint32_t userNum = 1002;
    UserInfo info = {};
    for (uint32_t i = 0; i < userNum; ++i) {
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
    CredentialInfoHal info = {};
    info.credentialId = 10;
    uint64_t condition = 10;
    EXPECT_TRUE(MatchCredentialById(static_cast<void *>(&info), static_cast<void *>(&condition)));
    condition = 20;
    EXPECT_FALSE(MatchCredentialById(static_cast<void *>(&info), static_cast<void *>(&condition)));
}

HWTEST_F(IdmDatabaseTest, TestMatchEnrolledInfoByType, TestSize.Level0)
{
    EXPECT_FALSE(MatchEnrolledInfoByType(nullptr, nullptr));
    EnrolledInfoHal info = {};
    info.authType = 1;
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
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = 112;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    CredentialInfoHal credInfo = {};
    EXPECT_EQ(DeleteCredentialInfo(112, 1, &credInfo), RESULT_UNKNOWN);
}

HWTEST_F(IdmDatabaseTest, TestDeleteCredentialInfo_003, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = 113;
    userInfo.enrolledInfoList = nullptr;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    auto *credInfo = static_cast<CredentialInfoHal *>(Malloc(sizeof(CredentialInfoHal)));
    credInfo->credentialId = 10;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(credInfo));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    CredentialInfoHal info = {};
    EXPECT_EQ(DeleteCredentialInfo(113, 10, &info), 10006);
}

HWTEST_F(IdmDatabaseTest, TestDeleteCredentialInfo_004, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = 115;
    userInfo.enrolledInfoList = nullptr;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    auto *credInfo1 = static_cast<CredentialInfoHal *>(Malloc(sizeof(CredentialInfoHal)));
    credInfo1->credentialId = 10;
    credInfo1->authType = 2;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(credInfo1));
    auto *credInfo2 = static_cast<CredentialInfoHal *>(Malloc(sizeof(CredentialInfoHal)));
    credInfo2->credentialId = 20;
    credInfo2->authType = 2;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(credInfo2));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    CredentialInfoHal info = {};
    EXPECT_EQ(DeleteCredentialInfo(115, 10, &info), RESULT_SUCCESS);
    Free(credInfo2);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialById, TestSize.Level0)
{
    EXPECT_EQ(QueryCredentialById(111, nullptr), nullptr);
    LinkedList *credentialList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(credentialList, nullptr);
    CredentialInfoHal credInfo1 = {};
    credInfo1.credentialId = 10;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo1));
    CredentialInfoHal credInfo2 = {};
    credInfo2.credentialId = 20;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo2));
    credentialList->insert(credentialList, nullptr);
    EXPECT_NE(QueryCredentialById(10, credentialList), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialByAuthType, TestSize.Level0)
{
    EXPECT_EQ(QueryCredentialByAuthType(1, nullptr), nullptr);
    LinkedList *credentialList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(credentialList, nullptr);
    CredentialInfoHal credInfo1 = {};
    credInfo1.authType = 1;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo1));
    CredentialInfoHal credInfo2 = {};
    credInfo2.authType = 2;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo2));
    credentialList->insert(credentialList, nullptr);
    EXPECT_NE(QueryCredentialByAuthType(1, credentialList), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestIsCredMatch_001, TestSize.Level0)
{
    CredentialInfoHal credInfo = {};
    credInfo.templateId = 20;
    CredentialCondition limit = {};
    SetCredentialConditionTemplateId(&limit, 10);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
}

HWTEST_F(IdmDatabaseTest, TestIsCredMatch_002, TestSize.Level0)
{
    CredentialInfoHal credInfo = {};
    credInfo.executorSensorHint = 20;
    CredentialCondition limit = {};
    SetCredentialConditionExecutorSensorHint(&limit, 0);
    EXPECT_TRUE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorSensorHint(&limit, 10);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorSensorHint(&limit, 20);
    EXPECT_TRUE(IsCredMatch(&limit, &credInfo));
}

HWTEST_F(IdmDatabaseTest, TestIsCredMatch_003, TestSize.Level0)
{
    CredentialInfoHal credInfo = {};
    credInfo.executorMatcher = 20;
    CredentialCondition limit = {};
    EXPECT_TRUE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorMatcher(&limit, 10);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorMatcher(&limit, 20);
    EXPECT_TRUE(IsCredMatch(&limit, &credInfo));
}

HWTEST_F(IdmDatabaseTest, TestIsUserMatch, TestSize.Level0)
{
    UserInfo userInfo = {};
    userInfo.userId = 20;
    CredentialCondition limit = {};
    SetCredentialConditionUserId(&limit, 10);
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
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo1 = {};
    userInfo1.userId = 1001;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo1));
    UserInfo userInfo2 = {};
    userInfo2.userId = 1002;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo2));
    CredentialCondition limit = {};
    SetCredentialConditionUserId(&limit, 1001);
    EXPECT_EQ(QueryCredentialLimit(&limit), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialUserId_001, TestSize.Level0)
{
    g_userInfoList = nullptr;
    EXPECT_EQ(QueryCredentialUserId(10, nullptr), RESULT_BAD_PARAM);
    int32_t userId = 1001;
    EXPECT_EQ(QueryCredentialUserId(10, &userId), RESULT_NEED_INIT);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    EXPECT_EQ(QueryCredentialUserId(10, &userId), RESULT_NOT_FOUND);
    g_userInfoList->insert(g_userInfoList, nullptr);
    EXPECT_EQ(QueryCredentialUserId(10, &userId), RESULT_UNKNOWN);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialUserId_002, TestSize.Level0)
{
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = 1002;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    int32_t userId = 1001;
    EXPECT_EQ(QueryCredentialUserId(10, &userId), RESULT_UNKNOWN);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialUserId_003, TestSize.Level0)
{
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = 1002;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    int32_t userId = 1001;
    EXPECT_EQ(QueryCredentialUserId(10, &userId), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestSetPinSubType, TestSize.Level0)
{
    g_userInfoList = nullptr;
    g_currentUser = nullptr;
    EXPECT_EQ(SetPinSubType(1003, 10000), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetPinSubType, TestSize.Level0)
{
    g_userInfoList = nullptr;
    g_currentUser = nullptr;
    EXPECT_EQ(GetPinSubType(1005, nullptr), RESULT_BAD_PARAM);
    uint64_t subType = 10000;
    EXPECT_EQ(GetPinSubType(1005, &subType), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionCredentialId, TestSize.Level0)
{
    SetCredentialConditionCredentialId(nullptr, 10);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionTemplateId, TestSize.Level0)
{
    SetCredentialConditionTemplateId(nullptr, 20);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionAuthType, TestSize.Level0)
{
    SetCredentialConditionAuthType(nullptr, 2);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionExecutorSensorHint, TestSize.Level0)
{
    SetCredentialConditionExecutorSensorHint(nullptr, 20);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionExecutorMatcher, TestSize.Level0)
{
    SetCredentialConditionExecutorMatcher(nullptr, 20);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionUserId, TestSize.Level0)
{
    SetCredentialConditionUserId(nullptr, 50);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
