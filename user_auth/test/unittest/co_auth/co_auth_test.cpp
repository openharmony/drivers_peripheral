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

extern "C" {
    extern LinkedList *g_poolList;
    extern LinkedList *g_scheduleList;
    extern bool IsScheduleMatch(const void *data, const void *condition);
    extern bool IsScheduleIdDuplicate(uint64_t scheduleId);
    extern ResultCode GenerateValidScheduleId(uint64_t *scheduleId);
    extern ResultCode MountExecutorOnce(const LinkedList *executors, CoAuthSchedule *coAuthSchedule,
        uint32_t sensorHint, uint32_t executorRole);
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
}

HWTEST_F(CoAuthTest, TestCopyCoAuthSchedule, TestSize.Level0)
{
    EXPECT_EQ(CopyCoAuthSchedule(nullptr), nullptr);
    CoAuthSchedule schedule = {};
    schedule.templateIds.num = 1;
    schedule.templateIds.value = nullptr;
    EXPECT_EQ(CopyCoAuthSchedule(&schedule), nullptr);
}

HWTEST_F(CoAuthTest, TestDestroyCoAuthSchedule, TestSize.Level0)
{
    DestroyCoAuthSchedule(nullptr);
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
    schedule.templateIds.num = 1;
    schedule.templateIds.value = nullptr;
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
    uint64_t scheduleId = 32565;
    EXPECT_EQ(RemoveCoAuthSchedule(scheduleId), RESULT_NEED_INIT);
}

HWTEST_F(CoAuthTest, TestGetCoAuthSchedule, TestSize.Level0)
{
    g_scheduleList = nullptr;
    uint64_t scheduleId = 32565;
    EXPECT_EQ(GetCoAuthSchedule(scheduleId), nullptr);
    InitCoAuth();
    CoAuthSchedule schedule1 = {};
    schedule1.scheduleId = 32565;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule1));
    CoAuthSchedule schedule2 = {};
    schedule2.scheduleId = 3200;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule2));
    g_scheduleList->insert(g_scheduleList, nullptr);
    EXPECT_NE(GetCoAuthSchedule(scheduleId), nullptr);
}

HWTEST_F(CoAuthTest, TestIsScheduleIdDuplicate, TestSize.Level0)
{
    g_scheduleList = nullptr;
    uint64_t scheduleId = 36163;
    InitCoAuth();
    EXPECT_FALSE(IsScheduleIdDuplicate(scheduleId));
    CoAuthSchedule schedule1 = {};
    schedule1.scheduleId = 36163;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule1));
    CoAuthSchedule schedule2 = {};
    schedule2.scheduleId = 3200;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule2));
    g_scheduleList->insert(g_scheduleList, nullptr);
    EXPECT_TRUE(IsScheduleIdDuplicate(scheduleId));
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
    uint32_t sensorHint = 3565;
    uint32_t executorRole = 6636;
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, sensorHint, executorRole), RESULT_NOT_FOUND);
    executor->insert(executor, nullptr);
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, sensorHint, executorRole), RESULT_UNKNOWN);
}

HWTEST_F(CoAuthTest, TestMountExecutorOnce_002, TestSize.Level0)
{
    LinkedList *executor = CreateLinkedList(DestroyExecutorInfo);
    CoAuthSchedule schedule = {};
    uint32_t sensorHint = 0;
    uint32_t executorRole = 6636;
    ExecutorInfoHal info1 = {};
    info1.executorRole = 6636;
    info1.executorSensorHint = 10;
    executor->insert(executor, static_cast<void *>(&info1));
    ExecutorInfoHal info2 = {};
    info2.executorRole = 6636;
    info2.executorSensorHint = 20;
    executor->insert(executor, static_cast<void *>(&info2));
    ExecutorInfoHal info3 = {};
    info3.executorRole = 6110;
    executor->insert(executor, static_cast<void *>(&info3));
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, sensorHint, executorRole), RESULT_SUCCESS);
    sensorHint = 10;
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, sensorHint, executorRole), RESULT_SUCCESS);
}

HWTEST_F(CoAuthTest, TestMountExecutor_001, TestSize.Level0)
{
    g_poolList = nullptr;
    ScheduleParam param = {};
    param.collectorSensorHint = 1012;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_UNKNOWN);
    InitResourcePool();
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    DestroyResourcePool();
}

HWTEST_F(CoAuthTest, TestMountExecutor_002, TestSize.Level0)
{
    InitResourcePool();
    ScheduleParam param = {};
    param.collectorSensorHint = 0;
    param.verifierSensorHint = 0;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = 1024;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    DestroyResourcePool();
}

HWTEST_F(CoAuthTest, TestMountExecutor_003, TestSize.Level0)
{
    InitResourcePool();
    ScheduleParam param = {};
    param.collectorSensorHint = 1024;
    param.collectorSensorHint = 0;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.collectorSensorHint = 10;
    param.verifierSensorHint = 0;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = 10;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = 20;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    DestroyResourcePool();
}

HWTEST_F(CoAuthTest, TestMountExecutor_004, TestSize.Level0)
{
    g_poolList = nullptr;
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.authType = 1;
    info.executorRole = 3;
    info.executorSensorHint = 10;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));

    ScheduleParam param = {};
    param.authType = 1;
    param.collectorSensorHint = 0;
    param.verifierSensorHint = 0;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_SUCCESS);
}

HWTEST_F(CoAuthTest, TestMountExecutor_005, TestSize.Level0)
{
    g_poolList = nullptr;
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.authType = 1;
    info.executorRole = 3;
    info.executorSensorHint = 10;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));

    ScheduleParam param = {};
    param.authType = 1;
    param.collectorSensorHint = 101;
    param.verifierSensorHint = 201;
    param.scheduleMode = SCHEDULE_MODE_IDENTIFY;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_GENERAL_ERROR);
    param.scheduleMode = SCHEDULE_MODE_AUTH;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = 10;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.collectorSensorHint = 10;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_SUCCESS);
}

HWTEST_F(CoAuthTest, TestGetScheduleVeriferSensorHint_001, TestSize.Level0)
{
    EXPECT_EQ(GetScheduleVeriferSensorHint(nullptr), INVALID_SENSOR_HINT);
    CoAuthSchedule schedule = {};
    ExecutorInfoHal info = {};
    info.executorSensorHint = 10;
    info.executorRole = VERIFIER;
    schedule.executorSize = 1;
    schedule.executors[0] = info;
    EXPECT_EQ(GetScheduleVeriferSensorHint(&schedule), info.executorSensorHint);
}

HWTEST_F(CoAuthTest, TestGetScheduleVeriferSensorHint_002, TestSize.Level0)
{
    CoAuthSchedule schedule = {};
    ExecutorInfoHal info = {};
    info.executorSensorHint = 10;
    info.executorRole = COLLECTOR;
    schedule.executorSize = 1;
    schedule.executors[0] = info;
    EXPECT_EQ(GetScheduleVeriferSensorHint(&schedule), INVALID_SENSOR_HINT);
    schedule.executors[0].executorRole = ALL_IN_ONE;
    EXPECT_EQ(GetScheduleVeriferSensorHint(&schedule), info.executorSensorHint);
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
    g_scheduleList = nullptr;
    InitCoAuth();
    ScheduleParam param = {};
    param.templateIds = nullptr;
    EXPECT_EQ(GenerateSchedule(&param), nullptr);
    TemplateIdArrays array = {};
    array.num = 1;
    array.value = nullptr;
    param.templateIds = &array;
    EXPECT_EQ(GenerateSchedule(&param), nullptr);
    uint64_t temp = 1024;
    array.value = &temp;
    EXPECT_EQ(GenerateSchedule(&param), nullptr);
}

HWTEST_F(CoAuthTest, TestIsTemplateArraysValid, TestSize.Level0)
{
    EXPECT_FALSE(IsTemplateArraysValid(nullptr));
    TemplateIdArrays array = {};
    array.num = 200;
    array.value = nullptr;
    EXPECT_FALSE(IsTemplateArraysValid(&array));
    array.num = 1;
    EXPECT_FALSE(IsTemplateArraysValid(&array));
    uint64_t temp = 1024;
    array.value = &temp;
    EXPECT_TRUE(IsTemplateArraysValid(&array));
    array.num = 0;
    EXPECT_TRUE(IsTemplateArraysValid(&array));
}

HWTEST_F(CoAuthTest, TestCopyTemplateArrays, TestSize.Level0)
{
    EXPECT_EQ(CopyTemplateArrays(nullptr, nullptr), RESULT_BAD_PARAM);
    TemplateIdArrays inArray = {};
    inArray.num = 1;
    uint64_t temp = 1024;
    inArray.value = &temp;
    EXPECT_EQ(CopyTemplateArrays(&inArray, nullptr), RESULT_BAD_PARAM);
    TemplateIdArrays outArray = {};
    uint64_t num = 0;
    outArray.value = &num;
    EXPECT_EQ(CopyTemplateArrays(&inArray, &outArray), RESULT_BAD_PARAM);
    outArray.value = nullptr;
    EXPECT_EQ(CopyTemplateArrays(&inArray, &outArray), RESULT_SUCCESS);
    inArray.num = 0;
    outArray.value = nullptr;
    EXPECT_EQ(CopyTemplateArrays(&inArray, &outArray), RESULT_SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
