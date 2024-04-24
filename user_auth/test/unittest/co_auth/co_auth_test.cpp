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

extern "C" {
    extern LinkedList *g_poolList;
    extern LinkedList *g_scheduleList;
    extern bool IsScheduleMatch(const void *data, const void *condition);
    extern bool IsScheduleIdDuplicate(uint64_t scheduleId);
    extern ResultCode GenerateValidScheduleId(uint64_t *scheduleId);
    extern ResultCode MountExecutorOnce(const LinkedList *executors, CoAuthSchedule *coAuthSchedule,
        uint32_t sensorHint, uint32_t executorRole, Uint8Array deviceUdid);
    extern void DestroyExecutorInfo(void *data);
    extern ResultCode MountExecutor(const ScheduleParam *param, CoAuthSchedule *coAuthSchedule);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class CoAuthTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(CoAuthTest, TestDestroyScheduleNode, TestSize.Level0)
{
    DestroyScheduleNode(nullptr);
    CoAuthSchedule *schedule = (CoAuthSchedule *)Malloc(sizeof(CoAuthSchedule));
    EXPECT_NE(schedule, nullptr);
    ASSERT_NE(schedule, nullptr);
    (void)memset_s(schedule, sizeof(CoAuthSchedule), 0, sizeof(CoAuthSchedule));
    schedule->templateIds.data = (uint64_t *)Malloc(sizeof(uint64_t));
    EXPECT_NE(schedule->templateIds.data, nullptr);
    ASSERT_NE(schedule->templateIds.data, nullptr);
    schedule->templateIds.len = 1;
    DestroyScheduleNode(schedule);
}

HWTEST_F(CoAuthTest, TestCopyCoAuthSchedule, TestSize.Level0)
{
    EXPECT_EQ(CopyCoAuthSchedule(nullptr), nullptr);
    CoAuthSchedule schedule = {};
    schedule.templateIds.len = 1;
    schedule.templateIds.data = nullptr;
    EXPECT_EQ(CopyCoAuthSchedule(&schedule), nullptr);
}

HWTEST_F(CoAuthTest, TestDestroyCoAuthSchedule, TestSize.Level0)
{
    DestroyCoAuthSchedule(nullptr);
    CoAuthSchedule *schedule = (CoAuthSchedule *)Malloc(sizeof(CoAuthSchedule));
    EXPECT_NE(schedule, nullptr);
    ASSERT_NE(schedule, nullptr);
    (void)memset_s(schedule, sizeof(CoAuthSchedule), 0, sizeof(CoAuthSchedule));
    schedule->templateIds.data = (uint64_t *)Malloc(sizeof(uint64_t));
    EXPECT_NE(schedule->templateIds.data, nullptr);
    ASSERT_NE(schedule->templateIds.data, nullptr);
    schedule->templateIds.len = 1;
    DestroyCoAuthSchedule(schedule);
}

HWTEST_F(CoAuthTest, TestInitCoAuth, TestSize.Level0)
{
    InitCoAuth();
    EXPECT_EQ(InitCoAuth(), RESULT_SUCCESS);
    DestoryCoAuth();
}

HWTEST_F(CoAuthTest, TestAddCoAuthSchedule, TestSize.Level0)
{
    g_scheduleList = nullptr;
    EXPECT_EQ(AddCoAuthSchedule(nullptr), RESULT_NEED_INIT);
    InitCoAuth();
    EXPECT_EQ(AddCoAuthSchedule(nullptr), RESULT_BAD_PARAM);
    CoAuthSchedule schedule = {};
    schedule.templateIds.len = 1;
    schedule.templateIds.data = nullptr;
    EXPECT_EQ(AddCoAuthSchedule(&schedule), RESULT_NO_MEMORY);
    DestoryCoAuth();
}

HWTEST_F(CoAuthTest, TestIsScheduleMatch, TestSize.Level0)
{
    EXPECT_FALSE(IsScheduleMatch(nullptr, nullptr));
}

HWTEST_F(CoAuthTest, TestRemoveCoAuthSchedule, TestSize.Level0)
{
    g_scheduleList = nullptr;
    constexpr uint64_t scheduleId = 32565;
    EXPECT_EQ(RemoveCoAuthSchedule(scheduleId), RESULT_NEED_INIT);
}

HWTEST_F(CoAuthTest, TestGetCoAuthSchedule, TestSize.Level0)
{
    g_scheduleList = nullptr;
    constexpr uint64_t scheduleId1 = 32565;
    constexpr uint64_t scheduleId2 = 3200;
    EXPECT_EQ(GetCoAuthSchedule(scheduleId1), nullptr);
    InitCoAuth();
    CoAuthSchedule schedule1 = {};
    schedule1.scheduleId = scheduleId1;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule1));
    CoAuthSchedule schedule2 = {};
    schedule2.scheduleId = scheduleId2;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule2));
    g_scheduleList->insert(g_scheduleList, nullptr);
    EXPECT_NE(GetCoAuthSchedule(scheduleId1), nullptr);
}

HWTEST_F(CoAuthTest, TestIsScheduleIdDuplicate, TestSize.Level0)
{
    g_scheduleList = nullptr;
    constexpr uint64_t scheduleId1 = 36163;
    constexpr uint64_t scheduleId2 = 3200;
    InitCoAuth();
    EXPECT_FALSE(IsScheduleIdDuplicate(scheduleId1));
    CoAuthSchedule schedule1 = {};
    schedule1.scheduleId = scheduleId1;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule1));
    CoAuthSchedule schedule2 = {};
    schedule2.scheduleId = scheduleId2;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule2));
    g_scheduleList->insert(g_scheduleList, nullptr);
    EXPECT_TRUE(IsScheduleIdDuplicate(scheduleId1));
}

HWTEST_F(CoAuthTest, TestGenerateValidScheduleId, TestSize.Level0)
{
    g_scheduleList = nullptr;
    uint64_t scheduleId = 0;
    EXPECT_EQ(GenerateValidScheduleId(&scheduleId), RESULT_BAD_PARAM);
}

HWTEST_F(CoAuthTest, TestMountExecutorOnce_001, TestSize.Level0)
{
    LinkedList *executor = CreateLinkedList(DestroyExecutorInfo);
    CoAuthSchedule schedule = {};
    constexpr uint32_t sensorHint = 3565;
    constexpr uint32_t excutorRole = 6636;
    uint8_t deviceUdidBuffer[64] = { 0 };
    Uint8Array deviceUdid = { deviceUdidBuffer, 64 };
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, sensorHint, excutorRole, deviceUdid), RESULT_NOT_FOUND);
    executor->insert(executor, nullptr);
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, sensorHint, excutorRole, deviceUdid), RESULT_UNKNOWN);
}

HWTEST_F(CoAuthTest, TestMountExecutorOnce_002, TestSize.Level0)
{
    LinkedList *executor = CreateLinkedList(DestroyExecutorInfo);
    CoAuthSchedule schedule = {};
    constexpr uint32_t excutorSensorHint1 = 10;
    constexpr uint32_t excutorSensorHint2 = 20;
    constexpr uint32_t excutorRole1 = 6636;
    constexpr uint32_t excutorRole2 = 6110;
    uint32_t sensorHint = 0;
    uint32_t executorRole = excutorRole1;
    ExecutorInfoHal info1 = {};
    info1.executorRole = excutorRole1;
    info1.executorSensorHint = excutorSensorHint1;
    executor->insert(executor, static_cast<void *>(&info1));
    ExecutorInfoHal info2 = {};
    info2.executorRole = excutorRole1;
    info2.executorSensorHint = excutorSensorHint2;
    executor->insert(executor, static_cast<void *>(&info2));
    ExecutorInfoHal info3 = {};
    info3.executorRole = excutorRole2;
    executor->insert(executor, static_cast<void *>(&info3));
    uint8_t deviceUdidBuffer[64] = { 0 };
    Uint8Array deviceUdid = { deviceUdidBuffer, 64 };
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, sensorHint, executorRole, deviceUdid), RESULT_SUCCESS);
    sensorHint = 10;
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, sensorHint, executorRole, deviceUdid), RESULT_SUCCESS);
}

HWTEST_F(CoAuthTest, TestMountExecutor_001, TestSize.Level0)
{
    constexpr uint32_t collectorSensorHint = 1012;
    g_poolList = nullptr;
    ScheduleParam param = {};
    param.collectorSensorHint = collectorSensorHint;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_UNKNOWN);
    InitResourcePool();
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    DestroyResourcePool();
}

HWTEST_F(CoAuthTest, TestMountExecutor_002, TestSize.Level0)
{
    constexpr uint32_t verifierSensorHint = 1024;
    InitResourcePool();
    ScheduleParam param = {};
    param.collectorSensorHint = 0;
    param.verifierSensorHint = 0;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = verifierSensorHint;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    DestroyResourcePool();
}

HWTEST_F(CoAuthTest, TestMountExecutor_003, TestSize.Level0)
{
    constexpr uint32_t collectorSensorHint = 10;
    constexpr uint32_t verifierSensorHint_1 = 10;
    constexpr uint32_t verifierSensorHint_2 = 20;
    InitResourcePool();
    ScheduleParam param = {};
    param.collectorSensorHint = 0;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.collectorSensorHint = collectorSensorHint;
    param.verifierSensorHint = 0;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = verifierSensorHint_1;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = verifierSensorHint_2;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    DestroyResourcePool();
}

HWTEST_F(CoAuthTest, TestMountExecutor_004, TestSize.Level0)
{
    constexpr uint32_t authType = 1;
    constexpr uint32_t excutorRole = 3;
    constexpr uint32_t executorSensorHint = 10;
    g_poolList = nullptr;
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.authType = authType;
    info.executorRole = excutorRole;
    info.executorSensorHint = executorSensorHint;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));

    ScheduleParam param = {};
    param.authType = authType;
    param.collectorSensorHint = 0;
    param.verifierSensorHint = 0;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_SUCCESS);
}

HWTEST_F(CoAuthTest, TestMountExecutor_005, TestSize.Level0)
{
    constexpr uint32_t authType = 1;
    constexpr uint32_t excutorRole1 = 3;
    constexpr uint32_t executorSensorHint_1 = 10;
    constexpr uint32_t excutorRole2 = 101;
    constexpr uint32_t executorSensorHint_2 = 201;
    g_poolList = nullptr;
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.authType = authType;
    info.executorRole = excutorRole1;
    info.executorSensorHint = executorSensorHint_1;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));

    ScheduleParam param = {};
    param.authType = authType;
    param.collectorSensorHint = excutorRole2;
    param.verifierSensorHint = executorSensorHint_2;
    param.scheduleMode = SCHEDULE_MODE_IDENTIFY;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_GENERAL_ERROR);
    param.scheduleMode = SCHEDULE_MODE_AUTH;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = executorSensorHint_1;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.collectorSensorHint = executorSensorHint_1;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_SUCCESS);
}

HWTEST_F(CoAuthTest, TestGetScheduleVerifierSensorHint_001, TestSize.Level0)
{
    constexpr uint32_t executorSensorHint = 10;
    EXPECT_EQ(GetScheduleVerifierSensorHint(nullptr), INVALID_SENSOR_HINT);
    CoAuthSchedule schedule = {};
    ExecutorInfoHal info = {};
    info.executorSensorHint = executorSensorHint;
    info.executorRole = VERIFIER;
    schedule.executorSize = 1;
    schedule.executors[0] = info;
    EXPECT_EQ(GetScheduleVerifierSensorHint(&schedule), info.executorSensorHint);
}

HWTEST_F(CoAuthTest, TestGetScheduleVerifierSensorHint_002, TestSize.Level0)
{
    constexpr uint32_t executorSensorHint = 10;
    constexpr uint32_t excutorSize = 1;
    CoAuthSchedule schedule = {};
    ExecutorInfoHal info = {};
    info.executorSensorHint = executorSensorHint;
    info.executorRole = COLLECTOR;
    schedule.executorSize = excutorSize;
    schedule.executors[0] = info;
    EXPECT_EQ(GetScheduleVerifierSensorHint(&schedule), INVALID_SENSOR_HINT);
    schedule.executors[0].executorRole = ALL_IN_ONE;
    EXPECT_EQ(GetScheduleVerifierSensorHint(&schedule), info.executorSensorHint);
}

HWTEST_F(CoAuthTest, TestGenerateSchedule_001, TestSize.Level0)
{
    EXPECT_EQ(GenerateSchedule(nullptr), nullptr);
    g_scheduleList = nullptr;
    ScheduleParam param = {};
    EXPECT_EQ(GenerateSchedule(&param), nullptr);
}

HWTEST_F(CoAuthTest, TestGenerateSchedule_002, TestSize.Level0)
{
    constexpr uint32_t arrayLen = 1;
    constexpr uint32_t data = 1024;
    g_scheduleList = nullptr;
    InitCoAuth();
    ScheduleParam param = {};
    param.templateIds = nullptr;
    EXPECT_EQ(GenerateSchedule(&param), nullptr);
    Uint64Array array = {};
    array.len = arrayLen;
    array.data = nullptr;
    param.templateIds = &array;
    EXPECT_EQ(GenerateSchedule(&param), nullptr);
    uint64_t temp = data;
    array.data = &temp;
    EXPECT_EQ(GenerateSchedule(&param), nullptr);
}

HWTEST_F(CoAuthTest, TestIsTemplateArraysValid, TestSize.Level0)
{
    constexpr uint32_t arrayLen = 200;
    constexpr uint32_t data = 1024;
    EXPECT_FALSE(IsTemplateArraysValid(nullptr));
    Uint64Array array = {};
    array.len = arrayLen;
    array.data = nullptr;
    EXPECT_FALSE(IsTemplateArraysValid(&array));
    array.len = 1;
    EXPECT_FALSE(IsTemplateArraysValid(&array));
    uint64_t temp = data;
    array.data = &temp;
    EXPECT_TRUE(IsTemplateArraysValid(&array));
    array.len = 0;
    EXPECT_TRUE(IsTemplateArraysValid(&array));
}

HWTEST_F(CoAuthTest, TestCopyTemplateArrays, TestSize.Level0)
{
    constexpr uint32_t arrayLen = 1;
    constexpr uint32_t data = 1024;
    EXPECT_EQ(CopyTemplateArrays(nullptr, nullptr), RESULT_BAD_PARAM);
    Uint64Array inArray = {};
    inArray.len = arrayLen;
    uint64_t temp = data;
    inArray.data = &temp;
    EXPECT_EQ(CopyTemplateArrays(&inArray, nullptr), RESULT_BAD_PARAM);
    Uint64Array outArray = {};
    uint64_t num = 0;
    outArray.data = &num;
    EXPECT_EQ(CopyTemplateArrays(&inArray, &outArray), RESULT_BAD_PARAM);
    outArray.data = nullptr;
    EXPECT_EQ(CopyTemplateArrays(&inArray, &outArray), RESULT_SUCCESS);
    inArray.len = 0;
    outArray.data = nullptr;
    EXPECT_EQ(CopyTemplateArrays(&inArray, &outArray), RESULT_SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
