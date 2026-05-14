/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cmath>
#include <cstdio>
#include <unistd.h>
#include <cstdlib>
#include <sys/types.h>
#include <sys/wait.h>
#include <gtest/gtest.h>
#include <securec.h>
#include "hdf_base.h"
#include "osal_time.h"
#include "v3_0/isensor_interface.h"
#include "sensor_type.h"
#include "sensor_callback_impl.h"
#include "sensor_uhdf_log.h"
#include "sensor_trace.h"

using namespace OHOS::HDI::Sensor::V3_0;
using namespace OHOS::HDI::Sensor;
using namespace testing::ext;
int32_t SensorCallbackImpl::sensorDataCount = 0;
int32_t SensorCallbackImpl::sensorDataCountOld = 0;
bool SensorCallbackImpl::printDataFlag = false;

namespace {
struct ClientConfig {
    int32_t clientId;
    int64_t samplingIntervalNs;
    int32_t startDelayMs;
    int32_t activeDurationMs;
};

void RunClient(const ClientConfig &config)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("[Client%d] started (pid=%d)\n", config.clientId, getpid());

    if (config.startDelayMs > 0) {
        printf("[Client%d] waiting %dms before subscribing...\n", config.clientId, config.startDelayMs);
        OsalMSleep(config.startDelayMs);
    }

    sptr<V3_0::ISensorInterface> sensorInterface = V3_0::ISensorInterface::Get();
    if (sensorInterface == nullptr) {
        printf("[Client%d] ERROR: failed to get ISensorInterface\n", config.clientId);
        exit(1);
    }

    sptr<V3_0::ISensorCallback> callback = new SensorCallbackImpl();
    DeviceSensorInfo deviceSensorInfo = {-1, 1, 0, 1};

    SensorCallbackImpl::sensorDataCount = 0;
    SensorCallbackImpl::sensorDataCountOld = 0;

    int32_t ret = sensorInterface->Register(0, callback);
    if (ret != HDF_SUCCESS) {
        printf("[Client%d] ERROR: Register failed, ret=%d\n", config.clientId, ret);
        exit(1);
    }

    ret = sensorInterface->SetBatch(deviceSensorInfo, config.samplingIntervalNs, 0);
    printf("[Client%d] SetBatch interval=%sns, ret=%d\n",
        config.clientId, std::to_string(config.samplingIntervalNs).c_str(), ret);
    if (ret != HDF_SUCCESS) {
        printf("[Client%d] ERROR: SetBatch failed, ret=%d\n", config.clientId, ret);
        exit(1);
    }

    ret = sensorInterface->Enable(deviceSensorInfo);
    if (ret != HDF_SUCCESS) {
        printf("[Client%d] ERROR: Enable failed, ret=%d\n", config.clientId, ret);
        exit(1);
    }

    int32_t expectedPerSec = static_cast<int32_t>(1000000000 / config.samplingIntervalNs);
    int32_t minPerSec = std::max(1, expectedPerSec * 90 / 100);
    int32_t totalSeconds = config.activeDurationMs / 1000;

    printf("[Client%d] subscribed, expected %d/sec, min %d/sec, active for %ds\n",
        config.clientId, expectedPerSec, minPerSec, totalSeconds);

    for (int32_t i = 0; i < totalSeconds; i++) {
        OsalMSleep(1000);
        int32_t countPerSecond = SensorCallbackImpl::sensorDataCount - SensorCallbackImpl::sensorDataCountOld;
        SensorCallbackImpl::sensorDataCountOld = SensorCallbackImpl::sensorDataCount;
        if (countPerSecond >= minPerSec) {
            printf("\033[32m[Client%d][%ds] OK, 1s data count=%d (min=%d), total=%d\033[0m\n",
                config.clientId, i + 1, countPerSecond, minPerSec, SensorCallbackImpl::sensorDataCount);
        } else {
            printf("\033[31m[Client%d][%ds] [ERROR] 1s data count=%d (min=%d), total=%d\033[0m\n",
                config.clientId, i + 1, countPerSecond, minPerSec, SensorCallbackImpl::sensorDataCount);
        }
        fflush(stdout);
    }

    ret = sensorInterface->Disable(deviceSensorInfo);
    printf("[Client%d] Disable ret=%d\n", config.clientId, ret);

    ret = sensorInterface->Unregister(0, callback);
    printf("[Client%d] Unregister ret=%d\n", config.clientId, ret);

    printf("[Client%d] finished, total data=%d\n", config.clientId, SensorCallbackImpl::sensorDataCount);
    exit(0);
}

class SensorFourClientsForkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SensorFourClientsForkTest::SetUpTestCase() {}

void SensorFourClientsForkTest::TearDownTestCase() {}

void SensorFourClientsForkTest::SetUp() {}

void SensorFourClientsForkTest::TearDown() {}

HWTEST_F(SensorFourClientsForkTest, SensorFourClientsForkTest1, TestSize.Level1)
{
    ClientConfig configs[] = {
        {1, 1000000000, 0, 10000},
        {2, 100000000, 2000, 6000},
        {3, 10000000, 2000, 4000},
        {4, 5000000, 2000, 2000},
    };

    printf("[Parent] forking 4 client processes...\n");
    fflush(stdout);

    pid_t pids[4];
    for (int32_t i = 0; i < 4; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            RunClient(configs[i]);
        } else if (pids[i] < 0) {
            FAIL() << "fork() failed for client " << configs[i].clientId;
        }
        printf("[Parent] Client%d forked, pid=%d\n", configs[i].clientId, pids[i]);
        fflush(stdout);
    }

    printf("[Parent] all 4 clients forked, waiting for completion...\n");
    fflush(stdout);

    int32_t statuses[4];
    for (int32_t i = 0; i < 4; i++) {
        waitpid(pids[i], &statuses[i], 0);
        if (WIFEXITED(statuses[i])) {
            printf("[Parent] Client%d (pid=%d) exited with status %d\n",
                i + 1, pids[i], WEXITSTATUS(statuses[i]));
        } else {
            printf("[Parent] Client%d (pid=%d) exited abnormally\n", i + 1, pids[i]);
        }
        fflush(stdout);
    }

    bool allSuccess = true;
    for (int32_t i = 0; i < 4; i++) {
        if (!WIFEXITED(statuses[i]) || WEXITSTATUS(statuses[i]) != 0) {
            allSuccess = false;
        }
    }
    EXPECT_TRUE(allSuccess);

    printf("[Parent] test finished, allSuccess=%s\n", allSuccess ? "true" : "false");
}
}
