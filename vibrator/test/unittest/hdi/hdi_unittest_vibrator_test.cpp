#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>
#include <string>
#include "hdf_base.h"
#include "hdf_log.h"
#include "osal_time.h"
#include "parameters.h"
#include "v2_0/ivibrator_interface.h"

#define HDF_LOG_TAG "hdi_unittest_vibrator_test"
#define TEST_FUNC_IN HDF_LOGI("%{public}s in", testing::UnitTest::GetInstance()->current_test_info()->name())

using namespace std;
using namespace testing::ext;
using namespace OHOS::HDI::Vibrator;
using namespace OHOS::HDI::Vibrator::V2_0;

namespace {
    uint32_t g_duration = 1000;
    std::string g_effect1 = "haptic.long_press.light";
    HapticPaket g_pkg = {434, 1, {{V2_0::CONTINUOUS, 0, 149, 100, 50, 0, 4,
        {{0, 0, 0}, {1, 1, 0}, {32, 1, -39}, {149, 0, -39}}}}};
    V2_0::HapticPaket g_pkg1 = {434, 1, {{V2_0::TRANSIENT, 0, 149, 100, 50, 0, 4,
        {{0, 0, 0}, {1, 1, 0}, {32, 1, -39}, {149, 0, -39}}}}};
    V2_0::HapticPaket g_hapticPaket = {434, 1, {{V2_0::TRANSIENT, 0, 149, 100, 50, 0, 4,
        {{0, 0, 0}, {1, 1, 0}, {32, 1, -39}, {149, 0, -39}}}}};
    V2_0::VibratorPackage g_vibPackage = {434, 149, {{434, 1, {{V2_0::TRANSIENT, 0, 149, 100, 50, 0, 4,
        {{0, 0, 0}, {1, 1, 0}, {32, 1, -39}, {149, 0, -39}}}}}}};
    std::vector<HdfWaveInformation> g_info;
    const std::vector<std::string> g_effect{"haptic.long_press.light", "haptic.slide.light", \
        "haptic.threshold", "haptic.long_press.medium", "haptic.fail", "haptic.common.notice1", \
        "haptic.common.success", "haptic.charging", "haptic.long_press.heavy"};
    sptr<V2_0::IVibratorInterface> g_vibratorInterface = nullptr;
} // namespace

class HdiUnitTestVibrator : public testing::Test {
public:
    static void SetUpTestSuite();
    static void TearDownTestSuite();
    void SetUp();
    void TearDown();
};

void HdiUnitTestVibrator::SetUpTestSuite()
{
    g_vibratorInterface = V2_0::IVibratorInterface::Get();
}

void HdiUnitTestVibrator::TearDownTestSuite()
{
}

void HdiUnitTestVibrator::SetUp()
{
}

void HdiUnitTestVibrator::TearDown()
{
}

/**
  * @tc.name: CheckVibratorInstanceIsEmpty
  * @tc.desc: Create a Vibrator instance. The instance is not empty.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, CheckVibratorInstanceIsEmpty001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);
}

/**
  * @tc.name: VibratorStartOnceTest001
  * @tc.desc: Start one-shot vibration with given duration.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, VibratorStartOnceTest001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->StartOnce({0, 0}, g_duration);
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMSleep(2000);
}

/**
  * @tc.name: VibratorStartTest001
  * @tc.desc: Start periodic vibration with preset effect.
  * @tc.type: FUNC
  * @tc.require: #IAU5KS
  */
HWTEST_F(HdiUnitTestVibrator, VibratorStartTest001, TestSize.Level1)
{
    TEST_FUNC_IN;
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t ret = g_vibratorInterface->Start({0, 0}, "haptic.pattern.type1");
    HDF_LOGD("ret:%{public}d", ret);
    EXPECT_EQ(HDF_SUCCESS, ret);
    OsalMSleep(2000);
}