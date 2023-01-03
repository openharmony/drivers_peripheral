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

#include "coauth.h"
#include "executor_message.h"
#include "idm_common.h"
#include "tlv_base.h"

extern "C" {
    extern LinkedList *g_poolList;
    extern LinkedList *g_scheduleList;
    extern LinkedList *g_userInfoList;
    extern ResultCode ParseExecutorResultRemainTime(ExecutorResultInfo *result, TlvListNode *body);
    extern ResultCode ParseExecutorResultFreezingTime(ExecutorResultInfo *result, TlvListNode *body);
    extern ResultCode ParseExecutorResultAcl(ExecutorResultInfo *result, TlvListNode *body);
    extern ResultCode ParseExecutorResultTemplateId(ExecutorResultInfo *result, TlvListNode *body);
    extern ResultCode ParseExecutorResultScheduleId(ExecutorResultInfo *result, TlvListNode *body);
    extern ResultCode ParseExecutorResultCode(ExecutorResultInfo *result, TlvListNode *body);
    extern ResultCode ParseExecutorResultAuthSubType(ExecutorResultInfo *result, TlvListNode *body);
    extern ResultCode ParseExecutorResultInfo(const Buffer *data, ExecutorResultInfo *result);
    extern Buffer *ParseExecutorResultData(TlvListNode *body);
    extern Buffer *ParseExecutorResultSign(TlvListNode *body);
    extern ResultCode ParseRoot(ExecutorResultInfo *result, TlvListNode *body);
    extern bool IsExecutorInfoValid(const ExecutorResultInfo *executorResultInfo, const Buffer *data,
        const Buffer *sign);
    extern Buffer *SerializeExecutorMsgData(uint32_t authType, uint32_t propertyMode,
        const TemplateIdArrays *templateIds);
    extern Buffer *SerializeExecutorMsg(const Buffer *data, const Buffer *signatrue);
    extern Buffer *SerializeRootMsg(const Buffer *msg);
    extern Buffer *CreateExecutorMsg(uint32_t authType, uint32_t authPropertyMode,
        const TemplateIdArrays *templateIds);
    extern void DestoryExecutorMsg(void *data);
    extern ResultCode GetExecutorTemplateList(const ExecutorInfoHal *executorNode, TemplateIdArrays *templateIds);
    extern ResultCode AssemblyMessage(const ExecutorInfoHal *executorNode, uint32_t authPropertyMode,
        LinkedList *executorMsg);
    extern ResultCode TraverseExecutor(uint32_t executorRole, uint32_t authPropertyMode, LinkedList *executorMsg);
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

HWTEST_F(ExecutorMessageTest, TestParseExecutorResultRemainTime, TestSize.Level0)
{
    ExecutorResultInfo info = {};
    EXPECT_EQ(ParseExecutorResultRemainTime(&info, nullptr), RESULT_GENERAL_ERROR);
}

HWTEST_F(ExecutorMessageTest, TestParseExecutorResultFreezingTime, TestSize.Level0)
{
    ExecutorResultInfo info = {};
    EXPECT_EQ(ParseExecutorResultFreezingTime(&info, nullptr), RESULT_GENERAL_ERROR);
}

HWTEST_F(ExecutorMessageTest, TestParseExecutorResultAcl, TestSize.Level0)
{
    ExecutorResultInfo info = {};
    EXPECT_EQ(ParseExecutorResultAcl(&info, nullptr), RESULT_GENERAL_ERROR);
}

HWTEST_F(ExecutorMessageTest, TestParseExecutorResultTemplateId, TestSize.Level0)
{
    ExecutorResultInfo info = {};
    EXPECT_EQ(ParseExecutorResultTemplateId(&info, nullptr), RESULT_GENERAL_ERROR);
}

HWTEST_F(ExecutorMessageTest, TestParseExecutorResultScheduleId, TestSize.Level0)
{
    ExecutorResultInfo info = {};
    EXPECT_EQ(ParseExecutorResultScheduleId(&info, nullptr), RESULT_GENERAL_ERROR);
}

HWTEST_F(ExecutorMessageTest, TestParseExecutorResultCode, TestSize.Level0)
{
    ExecutorResultInfo info = {};
    EXPECT_EQ(ParseExecutorResultCode(&info, nullptr), RESULT_GENERAL_ERROR);
}

HWTEST_F(ExecutorMessageTest, TestParseExecutorResultAuthSubType, TestSize.Level0)
{
    ExecutorResultInfo info = {};
    EXPECT_EQ(ParseExecutorResultAuthSubType(&info, nullptr), RESULT_GENERAL_ERROR);
}

HWTEST_F(ExecutorMessageTest, TestParseExecutorResultInfo, TestSize.Level0)
{
    Buffer *data = CreateBufferBySize(10);
    EXPECT_NE(data, nullptr);
    data->buf = nullptr;
    ExecutorResultInfo info = {};
    EXPECT_EQ(ParseExecutorResultInfo(data, &info), 1001);
    DestoryBuffer(data);
}

HWTEST_F(ExecutorMessageTest, TestParseExecutorResultData, TestSize.Level0)
{
    EXPECT_EQ(ParseExecutorResultData(nullptr), nullptr);
}

HWTEST_F(ExecutorMessageTest, TestParseExecutorResultSign, TestSize.Level0)
{
    EXPECT_EQ(ParseExecutorResultSign(nullptr), nullptr);
}

HWTEST_F(ExecutorMessageTest, TestParseRoot, TestSize.Level0)
{
    ExecutorResultInfo info = {};
    EXPECT_EQ(ParseRoot(&info, nullptr), RESULT_BAD_PARAM);
    TlvListNode node = {};
    node.next = nullptr;
    EXPECT_EQ(ParseRoot(&info, &node), RESULT_BAD_PARAM);
}

HWTEST_F(ExecutorMessageTest, TestCreateExecutorResultInfo, TestSize.Level0)
{
    EXPECT_EQ(CreateExecutorResultInfo(nullptr), nullptr);
    Buffer *tlv = CreateBufferBySize(10);
    EXPECT_NE(tlv, nullptr);
    EXPECT_EQ(CreateExecutorResultInfo(tlv), nullptr);
    DestoryBuffer(tlv);
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

HWTEST_F(ExecutorMessageTest, TestIsExecutorInfoValid_001, TestSize.Level0)
{
    EXPECT_FALSE(IsExecutorInfoValid(nullptr, nullptr, nullptr));
    g_scheduleList = nullptr;
    ExecutorResultInfo info = {};
    info.scheduleId = 3236;
    EXPECT_FALSE(IsExecutorInfoValid(&info, nullptr, nullptr));
}

HWTEST_F(ExecutorMessageTest, TestIsExecutorInfoValid_002, TestSize.Level0)
{
    InitCoAuth();
    CoAuthSchedule schedule = {};
    schedule.scheduleId = 3236;
    ExecutorInfoHal executorInfo = {};
    executorInfo.executorRole = VERIFIER;
    schedule.executorSize = 1;
    schedule.executors[0] = executorInfo;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule));
    ExecutorResultInfo info = {};
    info.scheduleId = 3236;
    EXPECT_FALSE(IsExecutorInfoValid(&info, nullptr, nullptr));
}

HWTEST_F(ExecutorMessageTest, TestIsExecutorInfoValid_003, TestSize.Level0)
{
    InitCoAuth();
    CoAuthSchedule schedule = {};
    schedule.scheduleId = 3236;
    ExecutorInfoHal executorInfo = {};
    executorInfo.executorRole = ALL_IN_ONE;
    schedule.executorSize = 2;
    schedule.executors[0] = executorInfo;
    schedule.executors[0].executorRole = COLLECTOR;
    schedule.executors[1] = executorInfo;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule));
    ExecutorResultInfo info = {};
    info.scheduleId = 3236;
    EXPECT_FALSE(IsExecutorInfoValid(&info, nullptr, nullptr));
}

HWTEST_F(ExecutorMessageTest, TestSerializeExecutorMsgData, TestSize.Level0)
{
    EXPECT_EQ(SerializeExecutorMsgData(1, 0, nullptr), nullptr);
    TemplateIdArrays array = {};
    array.num = 200;
    EXPECT_EQ(SerializeExecutorMsgData(1, 4, &array), nullptr);
    array.num = 1;
    array.value = nullptr;
    EXPECT_EQ(SerializeExecutorMsgData(1, 4, &array), nullptr);
}

HWTEST_F(ExecutorMessageTest, TestSerializeExecutorMsg_001, TestSize.Level0)
{
    Buffer *data = CreateBufferBySize(10);
    EXPECT_NE(data, nullptr);
    data->buf = nullptr;
    EXPECT_EQ(SerializeExecutorMsg(data, nullptr), nullptr);
    DestoryBuffer(data);
}

HWTEST_F(ExecutorMessageTest, TestSerializeExecutorMsg_002, TestSize.Level0)
{
    Buffer *data = CreateBufferBySize(10);
    EXPECT_NE(data, nullptr);
    data->contentSize = 2;
    EXPECT_NE(SerializeExecutorMsg(data, nullptr), nullptr);
    Buffer *sign = CreateBufferBySize(10);
    sign->buf = nullptr;
    EXPECT_EQ(SerializeExecutorMsg(data, sign), nullptr);
    DestoryBuffer(data);
    DestoryBuffer(sign);
}

HWTEST_F(ExecutorMessageTest, TestSerializeRootMsg, TestSize.Level0)
{
    Buffer *msg = CreateBufferBySize(10);
    EXPECT_NE(msg, nullptr);
    EXPECT_EQ(SerializeRootMsg(msg), nullptr);
}

HWTEST_F(ExecutorMessageTest, TestCreateExecutorMsg, TestSize.Level0)
{
    EXPECT_EQ(CreateExecutorMsg(1, 0, nullptr), nullptr);
    TemplateIdArrays array = {};
    array.num = 1;
    array.value = nullptr;
    EXPECT_EQ(CreateExecutorMsg(1, 0, &array), nullptr);
}

HWTEST_F(ExecutorMessageTest, TestDestoryExecutorMsg, TestSize.Level0)
{
    DestoryExecutorMsg(nullptr);
}

HWTEST_F(ExecutorMessageTest, TestGetExecutorTemplateList, TestSize.Level0)
{
    g_userInfoList = nullptr;
    ExecutorInfoHal info = {};
    info.authType = 1;
    info.executorSensorHint = 10;
    TemplateIdArrays array = {};
    EXPECT_EQ(GetExecutorTemplateList(&info, &array), RESULT_UNKNOWN);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    CredentialInfoHal credInfo = {};
    credInfo.authType = 1;
    credInfo.executorSensorHint = 10;
    uint32_t credNum = 102;
    for (uint32_t i = 0; i < credNum; ++i) {
        userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credInfo));
    }
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    EXPECT_EQ(GetExecutorTemplateList(&info, &array), RESULT_REACH_LIMIT);
    info.authType = 2;
    EXPECT_EQ(GetExecutorTemplateList(&info, &array), RESULT_SUCCESS);
}

HWTEST_F(ExecutorMessageTest, TestAssemblyMessage_001, TestSize.Level0)
{
    g_userInfoList = nullptr;
    ExecutorInfoHal info = {};
    info.authType = 1;
    info.executorSensorHint = 10;
    EXPECT_EQ(AssemblyMessage(&info, 2, nullptr), RESULT_UNKNOWN);
}

HWTEST_F(ExecutorMessageTest, TestAssemblyMessage_002, TestSize.Level0)
{
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    CredentialInfoHal credInfo = {};
    credInfo.authType = 1;
    credInfo.executorSensorHint = 10;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credInfo));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));

    ExecutorInfoHal info = {};
    info.authType = 1;
    info.executorSensorHint = 20;
    EXPECT_EQ(AssemblyMessage(&info, 2, nullptr), RESULT_SUCCESS);
    info.executorSensorHint = 10;
    EXPECT_EQ(AssemblyMessage(&info, 2, nullptr), RESULT_NO_MEMORY);
}

HWTEST_F(ExecutorMessageTest, TestTraverseExecutor, TestSize.Level0)
{
    g_poolList = nullptr;
    g_userInfoList = nullptr;
    EXPECT_EQ(TraverseExecutor(1, 0, nullptr), RESULT_UNKNOWN);
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.executorRole = VERIFIER;
    info.authType = 2;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));
    LinkedList *executorMsg = new LinkedList();
    EXPECT_EQ(TraverseExecutor(2, 0, executorMsg), RESULT_UNKNOWN);
    delete executorMsg;
}

HWTEST_F(ExecutorMessageTest, TestGetExecutorMsgList, TestSize.Level0)
{
    g_poolList = nullptr;
    g_userInfoList = nullptr;
    EXPECT_EQ(GetExecutorMsgList(2, nullptr), RESULT_BAD_PARAM);
    LinkedList *executorMsg = nullptr;
    EXPECT_EQ(GetExecutorMsgList(0, &executorMsg), RESULT_UNKNOWN);
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.executorRole = VERIFIER;
    info.authType = 1;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));
    EXPECT_EQ(GetExecutorMsgList(4, &executorMsg), RESULT_SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
