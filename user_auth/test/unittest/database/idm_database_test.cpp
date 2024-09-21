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
#include "securec.h"

typedef bool (*DuplicateCheckFunc)(LinkedList *collection, uint64_t value);

extern "C" {
    extern LinkedList *g_userInfoList;
    extern UserInfo *g_currentUser;
    extern GlobalConfigInfo g_globalConfigArray[MAX_GLOBAL_CONFIG_NUM];
    extern bool MatchUserInfo(const void *data, const void *condition);
    extern bool IsUserInfoValid(UserInfo *userInfo);
    extern UserInfo *QueryUserInfo(int32_t userId);
    extern bool IsSecureUidDuplicate(LinkedList *userInfoList, uint64_t secureUid);
    extern UserInfo *CreateUser(int32_t userId, int32_t userType);
    extern ResultCode DeleteUser(int32_t userId);
    extern bool IsCredentialIdDuplicate(LinkedList *userInfoList, uint64_t credentialId);
    extern bool IsEnrolledIdDuplicate(LinkedList *enrolledList, uint64_t enrolledId);
    extern ResultCode GenerateDeduplicateUint64(LinkedList *collection, uint64_t *destValue, DuplicateCheckFunc func);
    extern ResultCode UpdateEnrolledId(LinkedList *enrolledList, uint32_t authType);
    extern ResultCode AddCredentialToUser(UserInfo *user, CredentialInfoHal *credentialInfo);
    extern ResultCode AddUser(int32_t userId, CredentialInfoHal *credentialInfo, int32_t userType);
    extern bool MatchCredentialById(const void *data, const void *condition);
    extern bool MatchEnrolledInfoByType(const void *data, const void *condition);
    extern CredentialInfoHal *QueryCredentialById(uint64_t credentialId, LinkedList *credentialList);
    extern CredentialInfoHal *QueryCredentialByAuthType(uint32_t authType, LinkedList *credentialList);
    extern bool IsCredMatch(const CredentialCondition *limit, const CredentialInfoHal *credentialInfo);
    extern bool IsUserMatch(const CredentialCondition *limit, const UserInfo *user);
    extern ResultCode TraverseCredentialList(const CredentialCondition *limit, const LinkedList *credentialList,
        LinkedList *credListGet);
    extern void RemoveCachePin(UserInfo *user, bool *isRemoved);
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

HWTEST_F(IdmDatabaseTest, TestInitUserInfoList_001, TestSize.Level0)
{
    EXPECT_EQ(InitUserInfoList(), RESULT_SUCCESS);
    DestroyUserInfoList();
}

HWTEST_F(IdmDatabaseTest, TestInitUserInfoList_002, TestSize.Level0)
{
    constexpr int32_t userType = 1024;
    UserInfo *userInfo = InitUserInfoNode();
    EXPECT_EQ(InitUserInfoList(), RESULT_SUCCESS);
    EXPECT_NE(userInfo->userType, userType);
    DestroyUserInfoNode(userInfo);
    DestroyUserInfoList();
}

HWTEST_F(IdmDatabaseTest, TestMatchUserInfo, TestSize.Level0)
{
    EXPECT_FALSE(MatchUserInfo(nullptr, nullptr));
    int32_t condition = 4526;
    constexpr int32_t userId = 1133;
    UserInfo info = {};
    info.userId = userId;
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
    constexpr int32_t userId = 1133;
    EXPECT_EQ(GetSecureUid(userId, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfoAuthType_001, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr int32_t userId = 1166;
    constexpr uint32_t authType = 1;
    EXPECT_EQ(GetEnrolledInfoAuthType(userId, authType, nullptr), RESULT_BAD_PARAM);
    EnrolledInfoHal info = {};
    EXPECT_EQ(GetEnrolledInfoAuthType(userId, authType, &info), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfoAuthType_002, TestSize.Level0)
{
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    constexpr int32_t userId = 1135;
    constexpr uint32_t authType = 1;
    userInfo.userId = userId;
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    EnrolledInfoHal info = {};
    EXPECT_EQ(GetEnrolledInfoAuthType(userId, authType, &info), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfoAuthType_003, TestSize.Level0)
{
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    constexpr int32_t userId = 1135;
    constexpr uint32_t authType1 = 1;
    constexpr uint32_t authType2 = 2;
    userInfo.userId = userId;
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EnrolledInfoHal enrolledInfo = {};
    enrolledInfo.authType = authType2;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    g_userInfoList->insert(g_userInfoList, nullptr);
    EnrolledInfoHal info = {};
    EXPECT_EQ(GetEnrolledInfoAuthType(userId, authType1, &info), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledInfo, TestSize.Level0)
{
    constexpr int32_t userId = 1211;
    EXPECT_EQ(GetEnrolledInfo(userId, nullptr, nullptr), RESULT_BAD_PARAM);
    g_userInfoList = nullptr;
    g_currentUser = nullptr;
    EnrolledInfoHal *enrolledInfos = nullptr;
    uint32_t num = 0;
    EXPECT_EQ(GetEnrolledInfo(userId, &enrolledInfos, &num), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestDeleteUserInfo, TestSize.Level0)
{
    constexpr int32_t userId = 1155;
    EXPECT_EQ(DeleteUserInfo(userId, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestQueryUserInfo_001, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr int32_t userId1 = 123;
    constexpr int32_t userId2 = 1123;
    UserInfo userInfo = {};
    userInfo.userId = userId1;
    g_currentUser = &userInfo;
    EXPECT_NE(QueryUserInfo(userId1), nullptr);
    userInfo.userId = userId2;
    EXPECT_EQ(QueryUserInfo(userId1), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestQueryUserInfo_002, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    constexpr int32_t userId1 = 123;
    constexpr int32_t userId2 = 1336;
    UserInfo userInfo1 = {};
    userInfo1.userId = userId1;
    userInfo1.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo1.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo1));
    UserInfo userInfo2 = {};
    userInfo2.userId = userId2;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo2));
    g_userInfoList->insert(g_userInfoList, nullptr);
    EXPECT_NE(QueryUserInfo(userId1), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestIsSecureUidDuplicate, TestSize.Level0)
{
    constexpr uint64_t secUid = 1221;
    constexpr uint64_t secUid1 = 111;
    constexpr uint64_t secUid2 = 222;
    EXPECT_FALSE(IsSecureUidDuplicate(nullptr, secUid));
    LinkedList *userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(userInfoList, nullptr);
    EXPECT_FALSE(IsSecureUidDuplicate(userInfoList, secUid));
    UserInfo info1 = {};
    info1.secUid = secUid1;
    userInfoList->insert(userInfoList, static_cast<void *>(&info1));
    UserInfo info2 = info1;
    info2.secUid = secUid2;
    userInfoList->insert(userInfoList, static_cast<void *>(&info2));
    userInfoList->insert(userInfoList, nullptr);
    EXPECT_TRUE(IsSecureUidDuplicate(userInfoList, secUid1));
}

HWTEST_F(IdmDatabaseTest, TestCreateUser, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr int32_t userId = 123;
    EXPECT_EQ(CreateUser(userId, 0), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestDeleteUser, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr int32_t userId = 123;
    EXPECT_EQ(DeleteUser(userId), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestIsCredentialIdDuplicate, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr uint64_t credentialId1 = 1221;
    constexpr uint64_t credentialId2 = 10;
    EXPECT_TRUE(IsCredentialIdDuplicate(nullptr, credentialId1));
    g_userInfoList =  CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo info = {};
    info.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(info.credentialInfoList, nullptr);
    CredentialInfoHal credInfo = {};
    credInfo.credentialId = credentialId2;
    info.credentialInfoList->insert(info.credentialInfoList, static_cast<void *>(&credInfo));
    g_userInfoList->insert(g_userInfoList, &info);
    EXPECT_FALSE(IsCredentialIdDuplicate(nullptr, credentialId2));
}

HWTEST_F(IdmDatabaseTest, TestIsEnrolledIdDuplicate, TestSize.Level0)
{
    constexpr uint64_t enrolledId1 = 111;
    constexpr uint64_t enrolledId2 = 222;
    LinkedList *enrolledList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(enrolledList, nullptr);
    EnrolledInfoHal info1 = {};
    info1.enrolledId = enrolledId1;
    enrolledList->insert(enrolledList, static_cast<void *>(&info1));
    EnrolledInfoHal info2 = {};
    info2.enrolledId = enrolledId2;
    enrolledList->insert(enrolledList, static_cast<void *>(&info2));
    enrolledList->insert(enrolledList, nullptr);
    EXPECT_TRUE(IsEnrolledIdDuplicate(enrolledList, enrolledId1));
}

HWTEST_F(IdmDatabaseTest, TestGenerateDeduplicateUint64, TestSize.Level0)
{
    EXPECT_EQ(GenerateDeduplicateUint64(nullptr, nullptr, IsEnrolledIdDuplicate), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestUpdateEnrolledId, TestSize.Level0)
{
    constexpr uint32_t authType1 = 1;
    constexpr uint32_t authType2 = 2;
    LinkedList *enrolledList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(enrolledList, nullptr);
    EnrolledInfoHal info1 = {};
    info1.authType = authType1;
    enrolledList->insert(enrolledList, static_cast<void *>(&info1));
    EnrolledInfoHal info2 = {};
    info2.authType = authType2;
    enrolledList->insert(enrolledList, static_cast<void *>(&info2));
    enrolledList->insert(enrolledList, nullptr);
    EXPECT_EQ(UpdateEnrolledId(enrolledList, authType1), RESULT_SUCCESS);
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
    constexpr uint32_t credNum = 102;
    for (uint32_t i = 0; i < credNum; ++i) {
        userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credInfo));
    }
    EXPECT_EQ(AddCredentialToUser(&userInfo, nullptr), RESULT_EXCEED_LIMIT);
}

HWTEST_F(IdmDatabaseTest, TestAddUser, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = nullptr;
    EXPECT_EQ(AddUser(111, nullptr, 0), RESULT_NEED_INIT);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    constexpr uint32_t userNum = 1002;
    UserInfo info = {};
    for (uint32_t i = 0; i < userNum; ++i) {
        g_userInfoList->insert(g_userInfoList, static_cast<void *>(&info));
    }
    EXPECT_EQ(AddUser(111, nullptr, 0), RESULT_EXCEED_LIMIT);
}

HWTEST_F(IdmDatabaseTest, TestAddCredentialInfo_001, TestSize.Level0)
{
    EXPECT_EQ(AddCredentialInfo(111, nullptr, 0), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestAddCredentialInfo_002, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    constexpr int32_t userId = 100;
    constexpr int32_t userType = 2;
    constexpr uint32_t authType = 1;
    UserInfo *user = QueryUserInfo(userId);
    EXPECT_EQ(user, nullptr);
    user = CreateUser(userId, userType);
    EXPECT_NE(user->userType, 0);

    CredentialInfoHal credInfo = {};
    credInfo.authType = authType;
    EXPECT_EQ(AddUser(userId, &credInfo, userType), RESULT_SUCCESS);

    EXPECT_EQ(AddCredentialInfo(userId, &credInfo, userType), RESULT_SUCCESS);
}

HWTEST_F(IdmDatabaseTest, TestMatchCredentialById, TestSize.Level0)
{
    EXPECT_FALSE(MatchCredentialById(nullptr, nullptr));
    constexpr uint64_t credentialId = 10;
    CredentialInfoHal info = {};
    info.credentialId = credentialId;
    uint64_t condition = credentialId;
    EXPECT_TRUE(MatchCredentialById(static_cast<void *>(&info), static_cast<void *>(&condition)));
    condition = 20;
    EXPECT_FALSE(MatchCredentialById(static_cast<void *>(&info), static_cast<void *>(&condition)));
}

HWTEST_F(IdmDatabaseTest, TestMatchEnrolledInfoByType, TestSize.Level0)
{
    EXPECT_FALSE(MatchEnrolledInfoByType(nullptr, nullptr));
    constexpr uint32_t authType = 1;
    EnrolledInfoHal info = {};
    info.authType = authType;
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
    constexpr int32_t userId = 112;
    constexpr uint64_t credentialId = 1;
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = userId;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    CredentialInfoHal credInfo = {};
    EXPECT_EQ(DeleteCredentialInfo(userId, credentialId, &credInfo), RESULT_UNKNOWN);
}

HWTEST_F(IdmDatabaseTest, TestDeleteCredentialInfo_003, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    constexpr int32_t userId = 113;
    constexpr uint64_t credentialId = 10;
    UserInfo userInfo = {};
    userInfo.userId = userId;
    userInfo.enrolledInfoList = nullptr;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    auto *credInfo = static_cast<CredentialInfoHal *>(Malloc(sizeof(CredentialInfoHal)));
    credInfo->credentialId = credentialId;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(credInfo));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    CredentialInfoHal info = {};
    EXPECT_EQ(DeleteCredentialInfo(userId, credentialId, &info), RESULT_SUCCESS);
}

HWTEST_F(IdmDatabaseTest, TestDeleteCredentialInfo_004, TestSize.Level0)
{
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    constexpr int32_t userId = 115;
    constexpr uint32_t authType = 2;
    constexpr uint64_t credentialId1 = 10;
    constexpr uint64_t credentialId2 = 20;
    UserInfo userInfo = {};
    userInfo.userId = userId;
    userInfo.enrolledInfoList = nullptr;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    auto *credInfo1 = static_cast<CredentialInfoHal *>(Malloc(sizeof(CredentialInfoHal)));
    credInfo1->credentialId = credentialId1;
    credInfo1->authType = authType;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(credInfo1));
    auto *credInfo2 = static_cast<CredentialInfoHal *>(Malloc(sizeof(CredentialInfoHal)));
    credInfo2->credentialId = credentialId2;
    credInfo2->authType = authType;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(credInfo2));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    CredentialInfoHal info = {};
    EXPECT_EQ(DeleteCredentialInfo(userId, credentialId1, &info), RESULT_SUCCESS);
    Free(credInfo2);
}

HWTEST_F(IdmDatabaseTest, TestClearCachePin, TestSize.Level0)
{
    constexpr int32_t userId = 115;
    ClearCachePin(userId);
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    constexpr uint64_t credentialId1 = 10;
    UserInfo userInfo = {};
    userInfo.userId = userId;
    userInfo.enrolledInfoList = nullptr;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    auto *credInfo1 = static_cast<CredentialInfoHal *>(Malloc(sizeof(CredentialInfoHal)));
    credInfo1->credentialId = credentialId1;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(credInfo1));
    ClearCachePin(userId);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialById, TestSize.Level0)
{
    constexpr uint64_t credentialId = 111;
    constexpr uint64_t credentialId1 = 10;
    constexpr uint64_t credentialId2 = 20;
    EXPECT_EQ(QueryCredentialById(credentialId, nullptr), nullptr);
    LinkedList *credentialList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(credentialList, nullptr);
    CredentialInfoHal credInfo1 = {};
    credInfo1.credentialId = credentialId1;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo1));
    CredentialInfoHal credInfo2 = {};
    credInfo2.credentialId = credentialId2;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo2));
    credentialList->insert(credentialList, nullptr);
    EXPECT_NE(QueryCredentialById(credentialId1, credentialList), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialByAuthType, TestSize.Level0)
{
    constexpr uint32_t authType1 = 1;
    constexpr uint32_t authType2 = 2;
    EXPECT_EQ(QueryCredentialByAuthType(1, nullptr), nullptr);
    LinkedList *credentialList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(credentialList, nullptr);
    CredentialInfoHal credInfo1 = {};
    credInfo1.authType = authType1;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo1));
    CredentialInfoHal credInfo2 = {};
    credInfo2.authType = authType2;
    credentialList->insert(credentialList, static_cast<void *>(&credInfo2));
    credentialList->insert(credentialList, nullptr);
    EXPECT_NE(QueryCredentialByAuthType(authType1, credentialList), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestIsCredMatch_001, TestSize.Level0)
{
    constexpr uint64_t templateId1 = 20;
    constexpr uint64_t templateId2 = 10;
    CredentialInfoHal credInfo = {};
    credInfo.templateId = templateId1;
    CredentialCondition limit = {};
    SetCredentialConditionTemplateId(&limit, templateId2);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
}

HWTEST_F(IdmDatabaseTest, TestIsCredMatch_002, TestSize.Level0)
{
    constexpr uint32_t excutorSensorHint1 = 10;
    constexpr uint32_t excutorSensorHint2 = 20;
    CredentialInfoHal credInfo = {};
    credInfo.executorSensorHint = excutorSensorHint2;
    CredentialCondition limit = {};
    SetCredentialConditionExecutorSensorHint(&limit, 0);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorSensorHint(&limit, excutorSensorHint1);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorSensorHint(&limit, excutorSensorHint2);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
}

HWTEST_F(IdmDatabaseTest, TestIsCredMatch_003, TestSize.Level0)
{
    constexpr uint32_t executorMatcher1 = 10;
    constexpr uint32_t executorMatcher2 = 20;
    CredentialInfoHal credInfo = {};
    credInfo.executorMatcher = executorMatcher2;
    CredentialCondition limit = {};
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorMatcher(&limit, executorMatcher1);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
    SetCredentialConditionExecutorMatcher(&limit, executorMatcher2);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
    SetCredentiaConditionNeedCachePin(nullptr);
    EXPECT_FALSE(IsCredMatch(&limit, &credInfo));
    SetCredentiaConditionNeedCachePin(&limit);
    EXPECT_TRUE(IsCredMatch(&limit, &credInfo));
}

HWTEST_F(IdmDatabaseTest, TestIsUserMatch, TestSize.Level0)
{
    constexpr int32_t userId1 = 20;
    constexpr int32_t userId2 = 10;
    UserInfo userInfo = {};
    userInfo.userId = userId1;
    CredentialCondition limit = {};
    SetCredentialConditionUserId(&limit, userId2);
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
    constexpr int32_t userId1 = 1001;
    constexpr int32_t userId2 = 1002;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo1 = {};
    userInfo1.userId = userId1;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo1));
    UserInfo userInfo2 = {};
    userInfo2.userId = userId2;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo2));
    CredentialCondition limit = {};
    SetCredentialConditionUserId(&limit, userId1);
    EXPECT_EQ(QueryCredentialLimit(&limit), nullptr);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialUserId_001, TestSize.Level0)
{
    constexpr int32_t userId1 = 1001;
    constexpr uint64_t credentialId = 10;
    g_userInfoList = nullptr;
    EXPECT_EQ(QueryCredentialUserId(credentialId, nullptr), RESULT_BAD_PARAM);
    int32_t userId = userId1;
    EXPECT_EQ(QueryCredentialUserId(credentialId, &userId), RESULT_NEED_INIT);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    EXPECT_EQ(QueryCredentialUserId(credentialId, &userId), RESULT_NOT_FOUND);
    g_userInfoList->insert(g_userInfoList, nullptr);
    EXPECT_EQ(QueryCredentialUserId(credentialId, &userId), RESULT_UNKNOWN);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialUserId_002, TestSize.Level0)
{
    constexpr int32_t userId1 = 1002;
    constexpr int32_t userId2 = 1001;
    constexpr uint64_t credentialId = 10;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = userId1;
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    int32_t userId = userId2;
    EXPECT_EQ(QueryCredentialUserId(credentialId, &userId), RESULT_UNKNOWN);
}

HWTEST_F(IdmDatabaseTest, TestQueryCredentialUserId_003, TestSize.Level0)
{
    constexpr int32_t userId1 = 1002;
    constexpr int32_t userId2 = 1001;
    constexpr uint64_t credentialId = 10;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = userId1;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    int32_t userId = userId2;
    EXPECT_EQ(QueryCredentialUserId(credentialId, &userId), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestSetPinSubType, TestSize.Level0)
{
    g_userInfoList = nullptr;
    g_currentUser = nullptr;
    constexpr int32_t userId = 1003;
    constexpr uint64_t pinSubType = 10000;
    EXPECT_EQ(SetPinSubType(userId, pinSubType), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestGetPinSubType, TestSize.Level0)
{
    g_userInfoList = nullptr;
    g_currentUser = nullptr;
    constexpr int32_t userId = 1005;
    constexpr uint64_t pinSubType = 10000;
    EXPECT_EQ(GetPinSubType(userId, nullptr), RESULT_BAD_PARAM);
    uint64_t subType = pinSubType;
    EXPECT_EQ(GetPinSubType(userId, &subType), RESULT_NOT_FOUND);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionCredentialId, TestSize.Level0)
{
    constexpr uint64_t credentialId = 10;
    SetCredentialConditionCredentialId(nullptr, credentialId);
    CredentialCondition condition = {};
    SetCredentialConditionCredentialId(&condition, credentialId);
    EXPECT_EQ(condition.credentialId, credentialId);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_CREDENTIAL_ID, CREDENTIAL_CONDITION_CREDENTIAL_ID);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionTemplateId, TestSize.Level0)
{
    constexpr uint64_t templateId = 20;
    SetCredentialConditionTemplateId(nullptr, templateId);
    CredentialCondition condition = {};
    SetCredentialConditionTemplateId(&condition, templateId);
    EXPECT_EQ(condition.templateId, templateId);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_TEMPLATE_ID, CREDENTIAL_CONDITION_TEMPLATE_ID);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionAuthType, TestSize.Level0)
{
    constexpr uint32_t authType = 2;
    SetCredentialConditionAuthType(nullptr, authType);
    CredentialCondition condition = {};
    SetCredentialConditionAuthType(&condition, authType);
    EXPECT_EQ(condition.authType, authType);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_AUTH_TYPE, CREDENTIAL_CONDITION_AUTH_TYPE);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionExecutorSensorHint, TestSize.Level0)
{
    constexpr uint32_t executorSensorHint = 20;
    SetCredentialConditionExecutorSensorHint(nullptr, executorSensorHint);
    CredentialCondition condition = {};
    SetCredentialConditionExecutorSensorHint(&condition, executorSensorHint);
    EXPECT_EQ(condition.executorSensorHint, executorSensorHint);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_SENSOR_HINT, CREDENTIAL_CONDITION_SENSOR_HINT);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionExecutorMatcher, TestSize.Level0)
{
    constexpr uint32_t executorMatcher = 20;
    SetCredentialConditionExecutorMatcher(nullptr, executorMatcher);
    CredentialCondition condition = {};
    SetCredentialConditionExecutorMatcher(&condition, executorMatcher);
    EXPECT_EQ(condition.executorMatcher, executorMatcher);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_EXECUTOR_MATCHER, CREDENTIAL_CONDITION_EXECUTOR_MATCHER);
}

HWTEST_F(IdmDatabaseTest, TestSetCredentialConditionUserId, TestSize.Level0)
{
    constexpr int32_t userId = 50;
    SetCredentialConditionUserId(nullptr, userId);
    CredentialCondition condition = {};
    SetCredentialConditionUserId(&condition, userId);
    EXPECT_EQ(condition.userId, userId);
    EXPECT_EQ(condition.conditionFactor & CREDENTIAL_CONDITION_USER_ID, CREDENTIAL_CONDITION_USER_ID);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledState_001, TestSize.Level0)
{
    constexpr int32_t userId = 1;
    constexpr uint32_t authType = 1;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    UserInfo userInfo = {};
    userInfo.userId = userId;
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));

    EnrolledStateHal enrolledState = {};
    EXPECT_EQ(GetEnrolledState(0, authType, &enrolledState), RESULT_NOT_ENROLLED);
    EXPECT_EQ(GetEnrolledState(userId, authType, &enrolledState), RESULT_NOT_ENROLLED);
}

HWTEST_F(IdmDatabaseTest, TestGetEnrolledState_002, TestSize.Level0)
{
    constexpr static int32_t expectCredentialCount = 2;
    constexpr static int32_t testEnrolledId = 2;
    constexpr int32_t userId = 1;
    constexpr uint32_t authType = 1;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);

    UserInfo userInfo = {};
    userInfo.userId = userId;
    userInfo.enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    EnrolledInfoHal enrolledInfo = {1, testEnrolledId};
    userInfo.enrolledInfoList->insert(userInfo.enrolledInfoList, static_cast<void *>(&enrolledInfo));

    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    CredentialInfoHal credentialInfo = {0, 0, 1, 0, 0, 0};
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credentialInfo));
    CredentialInfoHal credentialInfo1 = {1, 1, 1, 1, 1, 1};
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credentialInfo1));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));

    EnrolledStateHal enrolledState = {};
    EXPECT_EQ(GetEnrolledState(userId, authType, &enrolledState), RESULT_SUCCESS);
    EXPECT_EQ(enrolledState.credentialDigest, testEnrolledId);
    EXPECT_EQ(enrolledState.credentialCount, expectCredentialCount);
}

HWTEST_F(IdmDatabaseTest, TestRemoveCachePin_001, TestSize.Level0)
{
    constexpr int32_t userId = 1;
    UserInfo userInfo = {};
    userInfo.userId = userId;
    bool removed = false;

    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    CredentialInfoHal credentialInfo = {0, 0, 2, 2, 3, 4};
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credentialInfo));
    CredentialInfoHal credentialInfo1 = {1, 1, 1, 1, 1, 1};
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credentialInfo1));

    RemoveCachePin(&userInfo, &removed);
    EXPECT_EQ(removed, false);
}

HWTEST_F(IdmDatabaseTest, TestSaveGlobalConfigParam, TestSize.Level0)
{
    memset_s(g_globalConfigArray, sizeof(GlobalConfigInfo) * MAX_GLOBAL_CONFIG_NUM, 0,
        sizeof(GlobalConfigInfo) * MAX_GLOBAL_CONFIG_NUM);
    EXPECT_EQ(SaveGlobalConfigParam(nullptr), RESULT_BAD_PARAM);

    GlobalConfigParamHal param = {};
    param.type = ENABLE_STATUS;
    param.value.enableStatus = true;
    param.userIdNum = 1;
    param.userIds[0] = 1;
    param.authTypeNum = 1;
    param.authTypes[0] = 1;
    EXPECT_EQ(SaveGlobalConfigParam(&param), RESULT_SUCCESS);
    EXPECT_EQ(SaveGlobalConfigParam(&param), RESULT_SUCCESS);
    param.authTypeNum = MAX_AUTH_TYPE_LEN + 1;
    EXPECT_EQ(SaveGlobalConfigParam(&param), RESULT_BAD_PARAM);
    param.userIdNum = MAX_USER + 1;
    EXPECT_EQ(SaveGlobalConfigParam(&param), RESULT_BAD_PARAM);

    GlobalConfigParamHal param1 = {};
    param1.type = PIN_EXPIRED_PERIOD;
    param1.value.pinExpiredPeriod = 1;
    EXPECT_EQ(SaveGlobalConfigParam(&param1), RESULT_BAD_PARAM);

    GlobalConfigParamHal param2 = {};
    EXPECT_EQ(SaveGlobalConfigParam(&param2), RESULT_BAD_PARAM);
}

HWTEST_F(IdmDatabaseTest, TestGetPinExpiredInfo, TestSize.Level0)
{
    int32_t userId = 1;
    EXPECT_EQ(GetPinExpiredInfo(userId, nullptr), RESULT_BAD_PARAM);

    PinExpiredInfo info = {};
    EXPECT_EQ(GetPinExpiredInfo(userId, &info), RESULT_SUCCESS);

    g_globalConfigArray[0].type = PIN_EXPIRED_PERIOD;
    g_globalConfigArray[0].value.pinExpiredPeriod = 1;
    g_currentUser = nullptr;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.userId = 1;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    CredentialInfoHal credentialInfo1 = {1, 1, 1, 1, 0, 1, 0};
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credentialInfo1));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    EXPECT_EQ(GetPinExpiredInfo(userId, &info), RESULT_SUCCESS);
}

HWTEST_F(IdmDatabaseTest, TestGetEnableStatus, TestSize.Level0)
{
    int32_t userId = 1;
    uint32_t authType = 1;
    EXPECT_EQ(GetEnableStatus(userId, authType), true);

    g_globalConfigArray[0].type = PIN_EXPIRED_PERIOD;
    g_globalConfigArray[0].value.pinExpiredPeriod = 1;
    EXPECT_EQ(GetEnableStatus(userId, authType), true);

    g_globalConfigArray[0].type = ENABLE_STATUS;
    g_globalConfigArray[0].value.enableStatus = false;
    g_globalConfigArray[0].authType = 0;
    g_globalConfigArray[0].userIds[0] = 0;
    EXPECT_EQ(GetEnableStatus(userId, authType), true);

    g_globalConfigArray[0].authType = 1;
    EXPECT_EQ(GetEnableStatus(userId, authType), false);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
