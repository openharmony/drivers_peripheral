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

#include <gtest/gtest.h>

#include "securec.h"

#include "adaptor_memory.h"
#include "coauth.h"
#include "executor_message.h"
#include "idm_common.h"

extern "C" {
    extern LinkedList *g_poolList;
    extern LinkedList *g_scheduleList;
    extern LinkedList *g_userInfoList;
    extern void DestroyUserInfoList(void);
    extern ResultCode SignData(const Uint8Array *dataTlv, Uint8Array *signDataTlv);
    extern ResultCode GetAttributeDataAndSignTlv(const Attribute *attribute, bool needSignature,
        Uint8Array *retDataAndSignTlv, bool needUserType);
    extern ResultCode Ed25519VerifyData(uint64_t scheduleId, Uint8Array dataTlv, Uint8Array signTlv);
    extern ResultCode VerifyDataTlvSignature(const Attribute *dataAndSignAttribute, const Uint8Array dataTlv);
    extern Attribute *CreateAttributeFromDataAndSignTlv(const Uint8Array dataAndSignTlv, bool needVerifySignature);
    extern Attribute *CreateAttributeFromExecutorMsg(const Uint8Array msg, bool needVerifySignature);
    extern void GetRootSecretFromAttribute(const Attribute *attribute, ExecutorResultInfo *resultInfo);
    extern ResultCode GetExecutorResultInfoFromAttribute(const Attribute *attribute, ExecutorResultInfo *resultInfo);
    extern Buffer *CreateExecutorMsg(uint32_t authType, uint32_t authPropertyMode,
        const Uint64Array *templateIds);
    extern void DestoryExecutorMsg(void *data);
    extern ResultCode GetExecutorTemplateList(
        int32_t userId, const ExecutorInfoHal *executorNode, Uint64Array *templateIds);
    extern ResultCode AssemblyMessage(
        int32_t userId, const ExecutorInfoHal *executorNode, uint32_t authPropertyMode, LinkedList *executorMsg);
    extern ResultCode TraverseExecutor(
        int32_t userId, uint32_t executorRole, uint32_t authPropertyMode, LinkedList *executorMsg);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class ExecutorMessageTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(ExecutorMessageTest, TestSignData, TestSize.Level0)
{
    constexpr uint32_t len = 32;
    Uint8Array dataTlv = { (uint8_t *)Malloc(len), len };
    Uint8Array signData = { (uint8_t *)Malloc(len), len };
    dataTlv.len = 0;
    ResultCode result = SignData(&dataTlv, &signData);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    (void)memset_s(dataTlv.data, dataTlv.len, 1, dataTlv.len);
    dataTlv.len = len;
    result = SignData(&dataTlv, &signData);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Free(dataTlv.data);
    Free(signData.data);
}

HWTEST_F(ExecutorMessageTest, TestGetAttributeDataAndSignTlv, TestSize.Level0)
{
    Uint8Array retData = { (uint8_t *)Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    ResultCode result = GetAttributeDataAndSignTlv(nullptr, false, &retData, false);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    constexpr uint32_t testUint32 = 123;
    constexpr int32_t testInt32 = 123;
    constexpr uint64_t testUint64 = 456;
    uint8_t testUint8Buffer[] = { 'a', 'b', 'c' };
    uint64_t testUint64Buffer[] = { 123, 456, 789 };
    Uint8Array testUint8Array = { testUint8Buffer, sizeof(testUint8Buffer) };
    Uint64Array testUint64Array = { testUint64Buffer, sizeof(testUint64Buffer) };
    result = SetAttributeUint32(attribute, AUTH_IDENTIFY_MODE, testUint32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeInt32(attribute, AUTH_RESULT_CODE, testInt32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint64(attribute, AUTH_SCHEDULE_ID, testUint64);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint8Array(attribute, AUTH_SIGNATURE, testUint8Array);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, testUint64Array);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = GetAttributeDataAndSignTlv(attribute, false, &retData, false);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetAttributeDataAndSignTlv(attribute, true, &retData, false);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Free(retData.data);
    FreeAttribute(&attribute);
}

HWTEST_F(ExecutorMessageTest, TestGetAttributeExecutorMsg, TestSize.Level0)
{
    Uint8Array retData = { (uint8_t *)Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    ResultCode result = GetAttributeExecutorMsg(nullptr, false, &retData, false);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    result = GetAttributeExecutorMsg(attribute, false, nullptr, false);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    retData.len = 0;
    result = GetAttributeExecutorMsg(attribute, false, &retData, false);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);

    constexpr uint32_t testUint32 = 123;
    constexpr int32_t testInt32 = 123;
    constexpr uint64_t testUint64 = 456;
    uint8_t testUint8Buffer[] = { 'a', 'b', 'c' };
    uint64_t testUint64Buffer[] = { 123, 456, 789 };
    Uint8Array testUint8Array = { testUint8Buffer, sizeof(testUint8Buffer) };
    Uint64Array testUint64Array = { testUint64Buffer, sizeof(testUint64Buffer) };
    result = SetAttributeUint32(attribute, AUTH_IDENTIFY_MODE, testUint32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeInt32(attribute, AUTH_RESULT_CODE, testInt32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint64(attribute, AUTH_SCHEDULE_ID, testUint64);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint8Array(attribute, AUTH_SIGNATURE, testUint8Array);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, testUint64Array);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = GetAttributeExecutorMsg(attribute, false, &retData, false);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    result = GetAttributeExecutorMsg(attribute, true, &retData, false);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Free(retData.data);
    FreeAttribute(&attribute);
}

HWTEST_F(ExecutorMessageTest, TestEd25519VerifyData, TestSize.Level0)
{
    uint64_t scheduleId = 0;
    uint8_t testUint8Buffer[] = { 'a', 'b', 'c' };
    Uint8Array dataTlv = { testUint8Buffer, sizeof(testUint8Buffer) };
    Uint8Array signData = { testUint8Buffer, sizeof(testUint8Buffer) };
    ResultCode result = Ed25519VerifyData(scheduleId, dataTlv, signData);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
}

HWTEST_F(ExecutorMessageTest, TestVerifyDataTlvSignature, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    constexpr uint32_t dataLen = 12;
    uint8_t array[dataLen] = { 1, 2, 3, 4, 5, 6 };
    Uint8Array dataTlv = { &array[0], dataLen };
    ResultCode result = SetAttributeUint8Array(attribute, AUTH_SIGNATURE, dataTlv);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint8Array(attribute, AUTH_DATA, dataTlv);
    EXPECT_EQ(result, RESULT_SUCCESS);
    uint64_t scheduleId = 10;
    result = SetAttributeUint64(attribute, AUTH_SCHEDULE_ID, scheduleId);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = VerifyDataTlvSignature(nullptr, dataTlv);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    FreeAttribute(&attribute);
}

HWTEST_F(ExecutorMessageTest, TestCreateAttributeFromDataAndSignTlv, TestSize.Level0)
{
    Uint8Array retInfo = { (uint8_t *)Malloc(MAX_EXECUTOR_SIZE), MAX_EXECUTOR_SIZE };
    Attribute *retAttribute = CreateAttributeFromDataAndSignTlv(retInfo, true);
    EXPECT_EQ(retAttribute, nullptr);
    retInfo.len = 0;
    retAttribute = CreateAttributeFromDataAndSignTlv(retInfo, true);
    EXPECT_EQ(retAttribute, nullptr);
    constexpr int32_t resultCode = 123;
    constexpr uint32_t authType1 = 1;
    constexpr uint64_t templateId = 456;
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    ResultCode result = SetAttributeInt32(attribute, AUTH_RESULT_CODE, resultCode);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint32(attribute, AUTH_TYPE, authType1);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint64(attribute, AUTH_TEMPLATE_ID, templateId);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetAttributeExecutorMsg(attribute, true, &retInfo, false);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);

    Uint8Array dataAndSignTlv = { (uint8_t *)Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
    EXPECT_NE(dataAndSignTlv.data, nullptr);
    Attribute *msgAttribute = CreateAttributeFromSerializedMsg(retInfo);
    EXPECT_EQ(msgAttribute, nullptr);
    result = GetAttributeUint8Array(msgAttribute, AUTH_ROOT, &dataAndSignTlv);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
    retAttribute = CreateAttributeFromDataAndSignTlv(dataAndSignTlv, true);
    EXPECT_EQ(retAttribute, nullptr);
    retAttribute = CreateAttributeFromDataAndSignTlv(dataAndSignTlv, false);
    EXPECT_EQ(retAttribute, nullptr);

    FreeAttribute(&retAttribute);
    FreeAttribute(&msgAttribute);
    Free(dataAndSignTlv.data);
    FreeAttribute(&attribute);
    Free(retInfo.data);
}

HWTEST_F(ExecutorMessageTest, TestCreateAttributeFromExecutorMsg, TestSize.Level0)
{
    Uint8Array msg = { (uint8_t *)Malloc(MAX_EXECUTOR_SIZE), MAX_EXECUTOR_SIZE };
    Attribute *retAttribute = CreateAttributeFromExecutorMsg(msg, true);
    EXPECT_EQ(retAttribute, nullptr);
    constexpr int32_t resultCode = 1;
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    ResultCode result = SetAttributeInt32(attribute, AUTH_RESULT_CODE, resultCode);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetAttributeExecutorMsg(attribute, true, &msg, false);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);

    retAttribute = CreateAttributeFromExecutorMsg(msg, false);
    EXPECT_EQ(retAttribute, nullptr);
    retAttribute = CreateAttributeFromExecutorMsg(msg, true);
    EXPECT_EQ(retAttribute, nullptr);
    int32_t retCode;
    result = GetAttributeInt32(attribute, AUTH_RESULT_CODE, &retCode);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(retCode, resultCode);
    FreeAttribute(&retAttribute);
    FreeAttribute(&attribute);
    Free(msg.data);
}

HWTEST_F(ExecutorMessageTest, TestGetRootSecretFromAttribute, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    ExecutorResultInfo resultInfo= {};
    GetRootSecretFromAttribute(attribute, &resultInfo);
    uint8_t testUint8Buffer[] = { 'a', 'b', 'c' };
    Uint8Array rootSecret = { testUint8Buffer, sizeof(testUint8Buffer) };
    ResultCode result = SetAttributeUint8Array(attribute, AUTH_ROOT_SECRET, rootSecret);
    EXPECT_EQ(result, RESULT_SUCCESS);
    GetRootSecretFromAttribute(attribute, &resultInfo);
    FreeAttribute(&attribute);
}

HWTEST_F(ExecutorMessageTest, TestGetExecutorResultInfoFromAttribute, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    ExecutorResultInfo resultInfo= {};
    ResultCode result = GetExecutorResultInfoFromAttribute(attribute, &resultInfo);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    constexpr int32_t resultCode = 0;
    result = SetAttributeInt32(attribute, AUTH_RESULT_CODE, resultCode);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetExecutorResultInfoFromAttribute(attribute, &resultInfo);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    constexpr uint64_t templateId = 123;
    result = SetAttributeUint64(attribute, AUTH_TEMPLATE_ID, templateId);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetExecutorResultInfoFromAttribute(attribute, &resultInfo);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    constexpr uint64_t scheduleId = 234;
    result = SetAttributeUint64(attribute, AUTH_SCHEDULE_ID, scheduleId);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetExecutorResultInfoFromAttribute(attribute, &resultInfo);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    constexpr uint64_t subType = 0;
    result = SetAttributeUint64(attribute, AUTH_SUB_TYPE, subType);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetExecutorResultInfoFromAttribute(attribute, &resultInfo);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    constexpr int32_t remainTimes = 10;
    result = SetAttributeInt32(attribute, AUTH_REMAIN_COUNT, remainTimes);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetExecutorResultInfoFromAttribute(attribute, &resultInfo);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    constexpr int32_t freezingTime = 0;
    result = SetAttributeInt32(attribute, AUTH_REMAIN_TIME, freezingTime);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetExecutorResultInfoFromAttribute(attribute, &resultInfo);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    constexpr uint32_t capabilityLevel = 2;
    result = SetAttributeUint32(attribute, AUTH_CAPABILITY_LEVEL, capabilityLevel);
    EXPECT_EQ(result, RESULT_SUCCESS);
    uint8_t testUint8Buffer[] = { 'a', 'b', 'c' };
    Uint8Array rootSecret = { testUint8Buffer, sizeof(testUint8Buffer) };
    result = SetAttributeUint8Array(attribute, AUTH_ROOT_SECRET, rootSecret);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetExecutorResultInfoFromAttribute(attribute, &resultInfo);
    EXPECT_EQ(resultInfo.result, resultCode);
    EXPECT_EQ(resultInfo.templateId, templateId);
    EXPECT_EQ(resultInfo.remainTimes, remainTimes);
    EXPECT_EQ(resultInfo.capabilityLevel, capabilityLevel);
    FreeAttribute(&attribute);
}

HWTEST_F(ExecutorMessageTest, TestCreateExecutorResultInfo, TestSize.Level0)
{
    Buffer *tlv = NULL;
    ExecutorResultInfo *resultInfo = CreateExecutorResultInfo(tlv);
    EXPECT_EQ(resultInfo, nullptr);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    constexpr int32_t resultCode = 0;
    ResultCode result = SetAttributeInt32(attribute, AUTH_RESULT_CODE, resultCode);
    EXPECT_EQ(result, RESULT_SUCCESS);
    constexpr uint64_t templateId = 123;
    result = SetAttributeUint64(attribute, AUTH_TEMPLATE_ID, templateId);
    EXPECT_EQ(result, RESULT_SUCCESS);
    constexpr uint64_t scheduleId = 234;
    result = SetAttributeUint64(attribute, AUTH_SCHEDULE_ID, scheduleId);
    EXPECT_EQ(result, RESULT_SUCCESS);
    constexpr uint64_t subType = 0;
    result = SetAttributeUint64(attribute, AUTH_SUB_TYPE, subType);
    EXPECT_EQ(result, RESULT_SUCCESS);
    constexpr int32_t remainTimes = 10;
    result = SetAttributeInt32(attribute, AUTH_REMAIN_COUNT, remainTimes);
    EXPECT_EQ(result, RESULT_SUCCESS);
    constexpr int32_t freezingTime = 0;
    result = SetAttributeInt32(attribute, AUTH_REMAIN_TIME, freezingTime);
    EXPECT_EQ(result, RESULT_SUCCESS);
    constexpr uint32_t capabilityLevel = 2;
    result = SetAttributeUint32(attribute, AUTH_CAPABILITY_LEVEL, capabilityLevel);
    EXPECT_EQ(result, RESULT_SUCCESS);
    constexpr uint32_t dataLen = 120;
    std::vector<uint8_t> data;
    data.resize(dataLen);
    Uint8Array retExtraInfo = { data.data(), data.size() };
    result = GetAttributeExecutorMsg(attribute, false, &retExtraInfo, false);
    EXPECT_EQ(result, RESULT_SUCCESS);
    Buffer *buf = CreateBufferByData(retExtraInfo.data, retExtraInfo.len);
    EXPECT_NE(buf, nullptr);
    resultInfo = CreateExecutorResultInfo(buf);
    EXPECT_EQ(resultInfo, nullptr);
    DestoryBuffer(buf);
    FreeAttribute(&attribute);
}

HWTEST_F(ExecutorMessageTest, TestDestoryExecutorResultInfo, TestSize.Level0)
{
    DestoryExecutorResultInfo(nullptr);
    ExecutorResultInfo *info1 = new ExecutorResultInfo();
    EXPECT_NE(info1, nullptr);
    info1->rootSecret = CreateBufferBySize(10);
    DestoryExecutorResultInfo(info1);
    ExecutorResultInfo *info2 = new ExecutorResultInfo();
    EXPECT_NE(info2, nullptr);
    info2->rootSecret = nullptr;
    DestoryExecutorResultInfo(info2);
}

HWTEST_F(ExecutorMessageTest, TestCreateExecutorMsg, TestSize.Level0)
{
    EXPECT_EQ(CreateExecutorMsg(1, 0, nullptr), nullptr);
    constexpr uint32_t dataLen = 1;
    Uint64Array array = {};
    array.len = dataLen;
    array.data = nullptr;
    EXPECT_EQ(CreateExecutorMsg(1, 0, &array), nullptr);
}

HWTEST_F(ExecutorMessageTest, TestDestoryExecutorMsg, TestSize.Level0)
{
    DestoryExecutorMsg(nullptr);
    ExecutorMsg *msg = (ExecutorMsg *)Malloc(sizeof(ExecutorMsg));
    EXPECT_NE(msg, nullptr);
    ASSERT_NE(msg, nullptr);
    (void)memset_s(msg, sizeof(ExecutorMsg), 0, sizeof(ExecutorMsg));
    DestoryExecutorMsg(msg);
}

HWTEST_F(ExecutorMessageTest, TestGetExecutorTemplateList, TestSize.Level0)
{
    constexpr uint32_t authType1 = 1;
    constexpr uint32_t authType2 = 2;
    constexpr uint32_t executorSensorHint = 10;
    g_userInfoList = nullptr;
    ExecutorInfoHal info = {};
    info.authType = authType1;
    info.executorSensorHint = executorSensorHint;
    Uint64Array array = {};
    EXPECT_EQ(GetExecutorTemplateList(0, &info, &array), RESULT_UNKNOWN);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    CredentialInfoHal credInfo = {};
    credInfo.authType = authType1;
    credInfo.executorSensorHint = executorSensorHint;
    constexpr uint32_t credNum = 102;
    for (uint32_t i = 0; i < credNum; ++i) {
        userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credInfo));
    }
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    EXPECT_EQ(GetExecutorTemplateList(0, &info, &array), RESULT_REACH_LIMIT);
    info.authType = authType2;
    EXPECT_EQ(GetExecutorTemplateList(0, &info, &array), RESULT_SUCCESS);
}

HWTEST_F(ExecutorMessageTest, TestAssemblyMessage_001, TestSize.Level0)
{
    constexpr uint32_t authType = 2;
    constexpr uint32_t executorSensorHint = 10;
    g_userInfoList = nullptr;
    ExecutorInfoHal info = {};
    info.authType = authType;
    info.executorSensorHint = executorSensorHint;
    EXPECT_EQ(AssemblyMessage(0, &info, 2, nullptr), RESULT_UNKNOWN);
}

HWTEST_F(ExecutorMessageTest, TestAssemblyMessage_002, TestSize.Level0)
{
    constexpr uint32_t authType = 1;
    constexpr uint32_t executorSensorHint_1 = 10;
    constexpr uint32_t executorSensorHint_2 = 20;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo *userInfo = static_cast<UserInfo *>(malloc(sizeof(UserInfo)));
    EXPECT_NE(userInfo, nullptr);
    static_cast<void>(memset_s(userInfo, sizeof(UserInfo), 0, sizeof(UserInfo)));
    userInfo->credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo->credentialInfoList, nullptr);
    CredentialInfoHal *credInfo = static_cast<CredentialInfoHal *>(malloc(sizeof(CredentialInfoHal)));
    EXPECT_NE(credInfo, nullptr);
    static_cast<void>(memset_s(credInfo, sizeof(CredentialInfoHal), 0, sizeof(CredentialInfoHal)));
    credInfo->authType = authType;
    credInfo->executorSensorHint = executorSensorHint_1;
    userInfo->credentialInfoList->insert(userInfo->credentialInfoList, static_cast<void *>(credInfo));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(userInfo));

    ExecutorInfoHal info = {};
    info.authType = authType;
    info.executorSensorHint = executorSensorHint_2;
    LinkedList *executorMsg = CreateLinkedList(DestoryExecutorMsg);
    EXPECT_EQ(AssemblyMessage(0, &info, 2, executorMsg), RESULT_SUCCESS);
    DestroyLinkedList(executorMsg);

    executorMsg = CreateLinkedList(DestoryExecutorMsg);
    info.executorSensorHint = executorSensorHint_1;
    EXPECT_EQ(AssemblyMessage(0, &info, 2, executorMsg), RESULT_SUCCESS);
    DestroyLinkedList(executorMsg);
    DestroyUserInfoList();
}

HWTEST_F(ExecutorMessageTest, TestTraverseExecutor, TestSize.Level0)
{
    constexpr uint32_t authType = 2;
    g_poolList = nullptr;
    g_userInfoList = nullptr;
    EXPECT_EQ(TraverseExecutor(0, 1, 0, nullptr), RESULT_UNKNOWN);
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.executorRole = VERIFIER;
    info.authType = authType;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));
    LinkedList *executorMsg = new LinkedList();
    EXPECT_EQ(TraverseExecutor(0, 2, 0, executorMsg), RESULT_UNKNOWN);
    delete executorMsg;
}

HWTEST_F(ExecutorMessageTest, TestGetExecutorMsgList, TestSize.Level0)
{
    constexpr uint32_t authType = 1;
    g_poolList = nullptr;
    g_userInfoList = nullptr;
    EXPECT_EQ(GetExecutorMsgList(1, 2, nullptr), RESULT_BAD_PARAM);
    LinkedList *executorMsg = nullptr;
    EXPECT_EQ(GetExecutorMsgList(1, 0, &executorMsg), RESULT_UNKNOWN);
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.executorRole = VERIFIER;
    info.authType = authType;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));
    EXPECT_EQ(GetExecutorMsgList(1, 4, &executorMsg), RESULT_SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
