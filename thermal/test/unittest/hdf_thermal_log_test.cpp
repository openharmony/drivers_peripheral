/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define private   public
#define protected public
#include "thermal_dfx.h"
#undef private
#undef protected
#include "file_ex.h"
#include "thermal_log.h"

using namespace OHOS::HDI;
using namespace OHOS::HDI::Thermal::V1_1;
using namespace testing::ext;

class HdfThermalLogTest : public testing::Test {
public:
    static bool CheckThread(const std::string &threadName);
    static void TearDownTestCase();
};

bool HdfThermalLogTest::CheckThread(const std::string &threadName)
{
    std::string file = "/data/local/tmp/psTp";
    std::string cmd = "ps -T -p " + std::to_string(getpid()) + " > " + file;
    system(cmd.c_str());
    std::string content;
    OHOS::LoadStringFromFile(file, content);
    return (std::string::npos != content.find(threadName));
}

void HdfThermalLogTest::TearDownTestCase()
{
    system("rm -rf /data/local/tmp/psTp");
}

namespace {
constexpr int32_t DEFAULT_WIDTH = 20;
constexpr int32_t DEFAULT_INTERVAL = 5000;
constexpr int32_t MIN_INTERVAL = 100;
} // namespace

namespace {
/**
 * @tc.name: HdfThermalLogTest001
 * @tc.desc: Tests that the created thread is running properly
 * @tc.type: FUNC
 */
HWTEST_F(HdfThermalLogTest, HdfThermalLogTest001, TestSize.Level0)
{
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest001: start.");
    auto &hdfLog = ThermalDfx::GetInstance();
    hdfLog.Init();
    // thermal log off skipped tests
    ASSERT_TRUE(hdfLog.enable_) << "HdfThermalLogTest001: thermal log off skipped tests.";
    hdfLog.DoWork();
    ThermalDfx::DestroyInstance();
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest001: end.");
}

/**
 * @tc.name: HdfThermalLogTest002
 * @tc.desc: Tests that the GetIntParameter Limiting minimum
 * @tc.type: FUNC
 */
HWTEST_F(HdfThermalLogTest, HdfThermalLogTest002, TestSize.Level0)
{
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest002: start.");
    auto &hdfLog = ThermalDfx::GetInstance();
    uint32_t def = 888;
    // The obtained value is less than the default value. Return the default value
    uint32_t minVal = hdfLog.width_ + 1;
    uint32_t width = hdfLog.GetIntParameter("persist.thermal.log.width", def, minVal);
    ASSERT_EQ(def, width);

    // The value obtained is greater than the value obtained by default
    minVal = hdfLog.width_ - 1;
    width = hdfLog.GetIntParameter("persist.thermal.log.width", def, minVal);
    ASSERT_EQ(hdfLog.width_, width);
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest002: end.");
}

/**
 * @tc.name: HdfThermalLogTest003
 * @tc.desc: Tests that the WidthWatchCallback Limiting minimum
 * @tc.type: FUNC
 */
HWTEST_F(HdfThermalLogTest, HdfThermalLogTest003, TestSize.Level0)
{
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest003: start.");
    auto &hdfLog = ThermalDfx::GetInstance();
    int32_t minVal = -5;
    int32_t maxVal = DEFAULT_WIDTH + 10;
    for (int32_t i = minVal; i < maxVal; ++i) {
        std::string value = std::to_string(i);
        hdfLog.WidthWatchCallback(value);
        if (i <= DEFAULT_WIDTH) {
            ASSERT_EQ(hdfLog.width_.load(), static_cast<uint8_t>(DEFAULT_WIDTH));
        } else {
            ASSERT_EQ(hdfLog.width_.load(), static_cast<uint8_t>(i));
        }
    }
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest003: end.");
}

/**
 * @tc.name: HdfThermalLogTest004
 * @tc.desc: Tests that the WidthWatchCallback abnormal value
 * @tc.type: FUNC
 */
HWTEST_F(HdfThermalLogTest, HdfThermalLogTest004, TestSize.Level0)
{
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest004: start.");
    auto &hdfLog = ThermalDfx::GetInstance();
    std::vector<std::string> abnormal = {"", "abc", "123abc", "890,0"};
    for (auto& it : abnormal) {
        hdfLog.WidthWatchCallback(it);
        ASSERT_EQ(hdfLog.width_.load(), static_cast<uint8_t>(DEFAULT_WIDTH)) <<
            "HdfThermalLogTest004 failed value = " << it;
    }
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest004: end.");
}

/**
 * @tc.name: HdfThermalLogTest005
 * @tc.desc: Tests that the IntervalWatchCallback Limiting minimum
 * @tc.type: FUNC
 */
HWTEST_F(HdfThermalLogTest, HdfThermalLogTest005, TestSize.Level0)
{
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest005: start.");
    auto &hdfLog = ThermalDfx::GetInstance();
    int32_t minVal = -5;
    int32_t maxVal = DEFAULT_INTERVAL + 10;
    for (int32_t i = minVal; i < maxVal; ++i) {
        std::string value = std::to_string(i);
        hdfLog.IntervalWatchCallback(value);
        if (i <= MIN_INTERVAL) {
            ASSERT_EQ(hdfLog.interval_.load(), static_cast<uint32_t>(MIN_INTERVAL));
        } else {
            ASSERT_EQ(hdfLog.interval_.load(), static_cast<uint32_t>(i));
        }
    }
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest005: end.");
}

/**
 * @tc.name: HdfThermalLogTest006
 * @tc.desc: Tests that the IntervalWatchCallback abnormal value
 * @tc.type: FUNC
 */
HWTEST_F(HdfThermalLogTest, HdfThermalLogTest006, TestSize.Level0)
{
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest006: start.");
    auto &hdfLog = ThermalDfx::GetInstance();
    std::vector<std::string> abnormal = {"", "abc", "123abc", "890,0"};
    for (auto& it : abnormal) {
        hdfLog.IntervalWatchCallback(it);
        ASSERT_EQ(hdfLog.interval_.load(), static_cast<uint32_t>(DEFAULT_INTERVAL)) <<
            "HdfThermalLogTest006 failed value = " << it;
    }
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest006: end.");
}

/**
 * @tc.name: HdfThermalLogTest007
 * @tc.desc: Tests that the EnableWatchCallback The thread starts and stops normally
 * @tc.type: FUNC
 */
HWTEST_F(HdfThermalLogTest, HdfThermalLogTest007, TestSize.Level0)
{
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest007: start.");
    auto &hdfLog = ThermalDfx::GetInstance();
    hdfLog.Init();
    // thermal log off skipped tests
    if (!hdfLog.enable_) {
        ThermalDfx::DestroyInstance();
        THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest007: thermal log off skipped tests.");
        return;
    }
    // Stop
    hdfLog.EnableWatchCallback("false");
    ASSERT_EQ(hdfLog.enable_, false);
    // Run
    hdfLog.EnableWatchCallback("true");
    ASSERT_EQ(hdfLog.enable_, true);
    ThermalDfx::DestroyInstance();
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest007: end.");
}

/**
 * @tc.name: HdfThermalLogTest008
 * @tc.desc: Test the data partition size calculation
 * @tc.type: FUNC
 */
#ifdef DATA_SIZE_HISYSEVENT_ENABLE
HWTEST_F(HdfThermalLogTest, HdfThermalLogTest008, TestSize.Level0)
{
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest008: start.");
    auto &hdfLog = ThermalDfx::GetInstance();
    hdfLog.Init();
    ASSERT_TRUE(hdfLog.enable_);
    hdfLog.DoWork();
    double dataSize = hdfLog.GetDeviceValidSize("/data");
    EXPECT_NE(dataSize, 0);
    dataSize = hdfLog.GetDeviceValidSize("");
    EXPECT_EQ(dataSize, 0);

    uint64_t getDirectorySize = hdfLog.GetDirectorySize("/data/log/thermal/thermal-log");
    EXPECT_NE(getDirectorySize, 0);
    getDirectorySize = hdfLog.GetDirectorySize("");
    EXPECT_EQ(getDirectorySize, 0);

    ThermalDfx::DestroyInstance();
    THERMAL_HILOGD(LABEL_TEST, "HdfThermalLogTest008: end.");
}
#endif
} // namespace
