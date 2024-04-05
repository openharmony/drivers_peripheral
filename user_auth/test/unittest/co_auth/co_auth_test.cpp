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
    constexpr uint64_t SCHEDULE_ID = 32565;
    EXPECT_EQ(RemoveCoAuthSchedule(SCHEDULE_ID), RESULT_NEED_INIT);
}

HWTEST_F(CoAuthTest, TestGetCoAuthSchedule, TestSize.Level0)
{
    g_scheduleList = nullptr;
    constexpr uint64_t SCHEDULE_ID_1 = 32565;
    constexpr uint64_t SCHEDULE_ID_2 = 3200;
    EXPECT_EQ(GetCoAuthSchedule(SCHEDULE_ID_1), nullptr);
    InitCoAuth();
    CoAuthSchedule schedule1 = {};
    schedule1.scheduleId = SCHEDULE_ID_1;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule1));
    CoAuthSchedule schedule2 = {};
    schedule2.scheduleId = SCHEDULE_ID_2;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule2));
    g_scheduleList->insert(g_scheduleList, nullptr);
    EXPECT_NE(GetCoAuthSchedule(SCHEDULE_ID_1), nullptr);
}

HWTEST_F(CoAuthTest, TestIsScheduleIdDuplicate, TestSize.Level0)
{
    g_scheduleList = nullptr;
    constexpr uint64_t SCHEDULE_ID_1 = 36163;
    constexpr uint64_t SCHEDULE_ID_2 = 3200;
    InitCoAuth();
    EXPECT_FALSE(IsScheduleIdDuplicate(SCHEDULE_ID_1));
    CoAuthSchedule schedule1 = {};
    schedule1.scheduleId = SCHEDULE_ID_1;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule1));
    CoAuthSchedule schedule2 = {};
    schedule2.scheduleId = SCHEDULE_ID_2;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule2));
    g_scheduleList->insert(g_scheduleList, nullptr);
    EXPECT_TRUE(IsScheduleIdDuplicate(SCHEDULE_ID_1));
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
    constexpr uint32_t SENSOR_HINT = 3565;
    constexpr uint32_t EXECUTOR_ROLE = 6636;
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, SENSOR_HINT, EXECUTOR_ROLE), RESULT_NOT_FOUND);
    executor->insert(executor, nullptr);
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, SENSOR_HINT, EXECUTOR_ROLE), RESULT_UNKNOWN);
}

HWTEST_F(CoAuthTest, TestMountExecutorOnce_002, TestSize.Level0)
{
    LinkedList *executor = CreateLinkedList(DestroyExecutorInfo);
    CoAuthSchedule schedule = {};
    constexpr uint32_t EXCUTOR_SENSOR_HINT_1 = 10;
    constexpr uint32_t EXCUTOR_SENSOR_HINT_2 = 20;
    constexpr uint32_t EXECUTOR_ROLE_1 = 6636;
    constexpr uint32_t EXECUTOR_ROLE_2 = 6110;
    uint32_t sensorHint = 0;
    uint32_t executorRole = EXECUTOR_ROLE_1;
    ExecutorInfoHal info1 = {};
    info1.executorRole = EXECUTOR_ROLE_1;
    info1.executorSensorHint = EXCUTOR_SENSOR_HINT_1;
    executor->insert(executor, static_cast<void *>(&info1));
    ExecutorInfoHal info2 = {};
    info2.executorRole = EXECUTOR_ROLE_1;
    info2.executorSensorHint = EXCUTOR_SENSOR_HINT_2;
    executor->insert(executor, static_cast<void *>(&info2));
    ExecutorInfoHal info3 = {};
    info3.executorRole = EXECUTOR_ROLE_2;
    executor->insert(executor, static_cast<void *>(&info3));
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, sensorHint, executorRole), RESULT_SUCCESS);
    sensorHint = 10;
    EXPECT_EQ(MountExecutorOnce(executor, &schedule, sensorHint, executorRole), RESULT_SUCCESS);
}

HWTEST_F(CoAuthTest, TestMountExecutor_001, TestSize.Level0)
{
    constexpr uint32_t COLLECTOR_SENSOR_HINT = 1012;
    g_poolList = nullptr;
    ScheduleParam param = {};
    param.collectorSensorHint = COLLECTOR_SENSOR_HINT;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_UNKNOWN);
    InitResourcePool();
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    DestroyResourcePool();
}

HWTEST_F(CoAuthTest, TestMountExecutor_002, TestSize.Level0)
{
    constexpr uint32_t VERIFIER_SENSOR_HINT = 1024;
    InitResourcePool();
    ScheduleParam param = {};
    param.collectorSensorHint = 0;
    param.verifierSensorHint = 0;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = VERIFIER_SENSOR_HINT;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    DestroyResourcePool();
}

HWTEST_F(CoAuthTest, TestMountExecutor_003, TestSize.Level0)
{
    constexpr uint32_t COLLECTOR_SENSOR_HINT = 10;
    constexpr uint32_t VERIFIER_SENSOR_HINT_1 = 10;
    constexpr uint32_t VERIFIER_SENSOR_HINT_2 = 20;
    InitResourcePool();
    ScheduleParam param = {};
    param.collectorSensorHint = 0;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.collectorSensorHint = COLLECTOR_SENSOR_HINT;
    param.verifierSensorHint = 0;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = VERIFIER_SENSOR_HINT_1;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = VERIFIER_SENSOR_HINT_2;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    DestroyResourcePool();
}

HWTEST_F(CoAuthTest, TestMountExecutor_004, TestSize.Level0)
{
    constexpr uint32_t AUTH_TYPE = 1;
    constexpr uint32_t EXECUTOR_ROLE = 3;
    constexpr uint32_t EXECUTOR_SENSOR_HINT = 10;
    g_poolList = nullptr;
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.authType = AUTH_TYPE;
    info.executorRole = EXECUTOR_ROLE;
    info.executorSensorHint = EXECUTOR_SENSOR_HINT;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));

    ScheduleParam param = {};
    param.authType = AUTH_TYPE;
    param.collectorSensorHint = 0;
    param.verifierSensorHint = 0;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_SUCCESS);
}

HWTEST_F(CoAuthTest, TestMountExecutor_005, TestSize.Level0)
{
    constexpr uint32_t AUTH_TYPE = 1;
    constexpr uint32_t EXECUTOR_ROLE_1 = 3;
    constexpr uint32_t EXECUTOR_SENSOR_HINT_1 = 10;
    constexpr uint32_t EXECUTOR_ROLE_2 = 101;
    constexpr uint32_t EXECUTOR_SENSOR_HINT_2 = 201;
    g_poolList = nullptr;
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.authType = AUTH_TYPE;
    info.executorRole = EXECUTOR_ROLE_1;
    info.executorSensorHint = EXECUTOR_SENSOR_HINT_1;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));

    ScheduleParam param = {};
    param.authType = AUTH_TYPE;
    param.collectorSensorHint = EXECUTOR_ROLE_2;
    param.verifierSensorHint = EXECUTOR_SENSOR_HINT_2;
    param.scheduleMode = SCHEDULE_MODE_IDENTIFY;
    CoAuthSchedule schedule = {};
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_GENERAL_ERROR);
    param.scheduleMode = SCHEDULE_MODE_AUTH;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.verifierSensorHint = EXECUTOR_SENSOR_HINT_1;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_NOT_FOUND);
    param.collectorSensorHint = EXECUTOR_SENSOR_HINT_1;
    EXPECT_EQ(MountExecutor(&param, &schedule), RESULT_SUCCESS);
}

HWTEST_F(CoAuthTest, TestGetScheduleVeriferSensorHint_001, TestSize.Level0)
{
    constexpr uint32_t EXECUTOR_SENSOR_HINT = 10;
    EXPECT_EQ(GetScheduleVeriferSensorHint(nullptr), INVALID_SENSOR_HINT);
    CoAuthSchedule schedule = {};
    ExecutorInfoHal info = {};
    info.executorSensorHint = EXECUTOR_SENSOR_HINT;
    info.executorRole = VERIFIER;
    schedule.executorSize = 1;
    schedule.executors[0] = info;
    EXPECT_EQ(GetScheduleVeriferSensorHint(&schedule), info.executorSensorHint);
}

HWTEST_F(CoAuthTest, TestGetScheduleVeriferSensorHint_002, TestSize.Level0)
{
    constexpr uint32_t EXECUTOR_SENSOR_HINT = 10;
    constexpr uint32_t EXECUTOR_SIZE = 1;
    CoAuthSchedule schedule = {};
    ExecutorInfoHal info = {};
    info.executorSensorHint = EXECUTOR_SENSOR_HINT;
    info.executorRole = COLLECTOR;
    schedule.executorSize = EXECUTOR_SIZE;
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
    constexpr uint32_t ARRAY_LEN = 1;
    constexpr uint32_t DATA = 1024;
    g_scheduleList = nullptr;
    InitCoAuth();
    ScheduleParam param = {};
    param.templateIds = nullptr;
    EXPECT_EQ(GenerateSchedule(&param), nullptr);
    Uint64Array array = {};
    array.len = ARRAY_LEN;
    array.data = nullptr;
    param.templateIds = &array;
    EXPECT_EQ(GenerateSchedule(&param), nullptr);
    uint64_t temp = DATA;
    array.data = &temp;
    EXPECT_EQ(GenerateSchedule(&param), nullptr);
}

HWTEST_F(CoAuthTest, TestIsTemplateArraysValid, TestSize.Level0)
{
    constexpr uint32_t ARRAY_LEN = 200;
    constexpr uint32_t DATA = 1024;
    EXPECT_FALSE(IsTemplateArraysValid(nullptr));
    Uint64Array array = {};
    array.len = ARRAY_LEN;
    array.data = nullptr;
    EXPECT_FALSE(IsTemplateArraysValid(&array));
    array.len = 1;
    EXPECT_FALSE(IsTemplateArraysValid(&array));
    uint64_t temp = DATA;
    array.data = &temp;
    EXPECT_TRUE(IsTemplateArraysValid(&array));
    array.len = 0;
    EXPECT_TRUE(IsTemplateArraysValid(&array));
}

HWTEST_F(CoAuthTest, TestCopyTemplateArrays, TestSize.Level0)
{
    constexpr uint32_t ARRAY_LEN = 1;
    constexpr uint32_t DATA = 1024;
    EXPECT_EQ(CopyTemplateArrays(nullptr, nullptr), RESULT_BAD_PARAM);
    Uint64Array inArray = {};
    inArray.len = ARRAY_LEN;
    uint64_t temp = DATA;
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
