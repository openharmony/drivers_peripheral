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

#include <cmath>
#include <cstdio>
#include <unistd.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <hdf_base.h>
#include "osal_time.h"
#include "v1_0/iinput_interfaces.h"
#include "input_type.h"
#include "input_callback_impl.h"
#include "input_uhdf_log.h"

using namespace OHOS::HDI::Input::V1_0;
using namespace testing::ext;

namespace {
    sptr<IInputInterfaces>  g_inputInterfaces = nullptr;
    sptr<IInputCallback> g_callback = nullptr;
    sptr<IInputCallback> g_hotplugCb = nullptr;

    constexpr int32_t INIT_DEFAULT_VALUE = 255;
    constexpr int32_t KEEP_ALIVE_TIME_MS = 3000;
    constexpr int32_t TOUCH_INDEX = 1;
    constexpr int32_t INVALID_INDEX = 5;
    constexpr int32_t MAX_DEVICES = 32;
    constexpr int32_t TEST_RESULT_LEN = 32;
}

class HdfInputHdiTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfInputHdiTest::SetUpTestCase()
{
    g_inputInterfaces = IInputInterfaces::Get(true);
    if (g_inputInterfaces != nullptr) {
        g_callback = new InputCallbackImpl(g_inputInterfaces, nullptr);
        g_hotplugCb = new InputCallbackImpl(g_inputInterfaces, g_callback);
    }
}

void HdfInputHdiTest::TearDownTestCase()
{
}

void HdfInputHdiTest::SetUp()
{
}

void HdfInputHdiTest::TearDown()
{
}

static void OpenOnlineDev(std::vector<DevDesc> sta)
{
    int32_t ret = g_inputInterfaces->ScanInputDevice(sta);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: scan device failed, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    for (int32_t i = 0; i < MAX_DEVICES; i++) {
        if (sta[i].devIndex == 0) {
            break;
        }
        ret = g_inputInterfaces->OpenInputDevice(sta[i].devIndex);
        if (ret != INPUT_SUCCESS) {
            HDF_LOGE("%s: open device[%d] failed, ret %d", __func__, sta[i].devIndex, ret);
        }
        ASSERT_EQ(ret, INPUT_SUCCESS);

        ret  = g_inputInterfaces->RegisterReportCallback(sta[i].devIndex, g_callback);
        if (ret != INPUT_SUCCESS) {
            HDF_LOGE("%s: register callback failed for device[%d], ret %d", __func__, sta[i].devIndex, ret);
        }
        ASSERT_EQ(ret, INPUT_SUCCESS);
    }
}

static void CloseOnlineDev(std::vector<DevDesc> sta)
{
    int32_t ret = g_inputInterfaces->ScanInputDevice(sta);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: scan device failed, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    for (int32_t i = 0; i < MAX_DEVICES; i++) {
        if (sta[i].devIndex == 0) {
            break;
        }
        ret = g_inputInterfaces->UnregisterReportCallback(sta[i].devIndex);
        HDF_LOGE("%{public}s: index = %{public}d", __func__, i);
        if (ret != INPUT_SUCCESS) {
            HDF_LOGE("%s: register callback failed for device[%d], ret %d", __func__, sta[i].devIndex, ret);
        }
        ASSERT_EQ(ret, INPUT_SUCCESS);

        ret = g_inputInterfaces->CloseInputDevice(sta[i].devIndex);
        if (ret != INPUT_SUCCESS) {
            HDF_LOGE("%s: close device[%d] failed, ret %d", __func__, sta[i].devIndex, ret);
        }
        ASSERT_EQ(ret, INPUT_SUCCESS);
    }
}

/**
  * @tc.name: GetInputClient001
  * @tc.desc: Get a client and check whether the client is empty.
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetInputClient001, TestSize.Level0)
{
    ASSERT_NE(nullptr, g_inputInterfaces);
}

/**
  * @tc.name: ScanInputDevice001
  * @tc.desc: scan input device test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, ScanInputDevice001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    std::vector<DevDesc> sta;

    HDF_LOGI("%s: [Hdi-Input] ScanInputDevice001 enter", __func__);
    int32_t ret;

    ret  = g_inputInterfaces->ScanInputDevice(sta);
    if (ret == INPUT_SUCCESS) {
        HDF_LOGE("%s: %d, %d, %d, %d", __func__, sta[0].devType, sta[0].devIndex, sta[1].devType, sta[1].devIndex);
    }

    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: OpenInputDev001
  * @tc.desc: open input device test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, OpenInputDevice001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [Hdi-Input] OpenInputDevice001 enter", __func__);

    int32_t ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: open device failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: OpenInputDev002
  * @tc.desc: open input device test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, OpenInputDevice002, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [Hdi-Input] OpenInputDevice002 enter", __func__);

    /* Device "5" is used for testing nonexistent device node */
    int32_t ret = g_inputInterfaces->OpenInputDevice(INVALID_INDEX);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: device %d does not exist, can't open it, ret %d", __func__, INVALID_INDEX, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: CloseInputDevice001
  * @tc.desc: close input device test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, CloseInputDevice001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] CloseInputDevice001 enter", __func__);

    int32_t ret = g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: close device failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: CloseInputDevice002
  * @tc.desc: close input device test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, CloseInputDevice002, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] CloseInputDevice002 enter", __func__);

    /* Device "5" is used for testing nonexistent device node */
    int32_t ret = g_inputInterfaces->CloseInputDevice(INVALID_INDEX);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: device %d doesn't exist, can't close it, ret %d", __func__, INVALID_INDEX, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetInputDevice001
  * @tc.desc: get input device info test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetInputDevice001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] GetInputDevice001 enter", __func__);
    struct DeviceInfo dev;

    int32_t ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: open device failed, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    ret = g_inputInterfaces->GetInputDevice(TOUCH_INDEX, dev);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device failed, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    HDF_LOGI("%s: devindex = %u, devType = %u", __func__, dev.devIndex, dev.devType);
    HDF_LOGI("%s: chipInfo = %s, vendorName = %s, chipName = %s",
        __func__, dev.chipInfo.c_str(), dev.vendorName.c_str(), dev.chipName.c_str());
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetInputDeviceList001
  * @tc.desc: get input device list info test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetInputDeviceList001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] GetInputDeviceList001 enter", __func__);
    int32_t ret;
    uint32_t num = 0;
    std::vector<DeviceInfo> dev;

    ret = g_inputInterfaces->GetInputDeviceList(num, dev, MAX_INPUT_DEV_NUM);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device list failed, ret %d", __func__, ret);
    }
    ret = num <= MAX_INPUT_DEV_NUM ? HDF_SUCCESS : HDF_FAILURE;  /* num <= MAX_INPUT_DEV_NUM return true */
    ASSERT_EQ(ret, HDF_SUCCESS);


    for (uint32_t i = 0; i < num; i++) {
        HDF_LOGI("%s: num = %u, device[%u]'s info is:", __func__, num, i);
        HDF_LOGI("%s: index = %u, devType = %u", __func__, dev[i].devIndex, dev[i].devType);
        HDF_LOGI("%s: chipInfo = %s, vendorName = %s, chipName = %s",
            __func__, dev[i].chipInfo.c_str(), dev[i].vendorName.c_str(), dev[i].chipName.c_str());
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetDeviceType001
  * @tc.desc: get input device type test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetDeviceType001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] GetDeviceType001 enter", __func__);
    int32_t ret;
    uint32_t devType = INIT_DEFAULT_VALUE;

    ret = g_inputInterfaces->GetDeviceType(TOUCH_INDEX, devType);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device's type failed, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    HDF_LOGI("%s: device's type is %u", __func__, devType);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipInfo001
  * @tc.desc: get input device chip info test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetChipInfo001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] GetChipInfo001 enter", __func__);
    int32_t ret;
    std::string chipInfo;

    ret = g_inputInterfaces->GetChipInfo(TOUCH_INDEX, chipInfo);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device's chip info failed, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    HDF_LOGI("%s: device's chip info is %s", __func__, chipInfo.c_str());
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetInputDevice002
  * @tc.desc: get input device chip info test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetInputDevice002, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }

    HDF_LOGI("%s: [hdi-input] GetInputDevice002 enter", __func__);
    struct DeviceInfo dev;

    int32_t ret = g_inputInterfaces->GetInputDevice(TOUCH_INDEX, dev);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device failed, ret %d", __func__, ret);
    }

    HDF_LOGI("%s: After fill the info, new device's info is:", __func__);
    HDF_LOGI("%s: new devIndex = %u, devType = %u", __func__, dev.devIndex, dev.devType);
    HDF_LOGI("%s: new chipInfo = %s, vendorName = %s, chipName = %s",
        __func__, dev.chipInfo.c_str(), dev.vendorName.c_str(), dev.chipName.c_str());
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RegisterCallback001
  * @tc.desc: register input device report test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, RegisterCallback001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] RegisterCallback001 enter", __func__);

    /* Device "5" is used for testing nonexistent device node */
    int32_t ret  = g_inputInterfaces->RegisterReportCallback(INVALID_INDEX, g_callback);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: device %d dose not exist, can't register callback to it, ret %d", __func__, INVALID_INDEX, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetPowerStatus001
  * @tc.desc: set device power status test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, SetPowerStatus001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] SetPowerStatus001 enter", __func__);
    int32_t ret;
    uint32_t setStatus = INPUT_LOW_POWER;

    ret = g_inputInterfaces->SetPowerStatus(TOUCH_INDEX, setStatus);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: set device's power status failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetPowerStatus002
  * @tc.desc: set device power status test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, SetPowerStatus002, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] SetPowerStatus002 enter", __func__);
    int32_t ret;
    uint32_t setStatus = INPUT_LOW_POWER;
    /* Device "5" is used for testing nonexistent device node */
    ret = g_inputInterfaces->SetPowerStatus(INVALID_INDEX, setStatus);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: set device %d's power status failed, ret %d", __func__, INVALID_INDEX, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetPowerStatus001
  * @tc.desc: get device power status test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetPowerStatus001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] GetPowerStatus001 enter", __func__);
    int32_t ret;
    uint32_t getStatus = 0;

    ret = g_inputInterfaces->GetPowerStatus(TOUCH_INDEX, getStatus);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device's power status failed, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    HDF_LOGI("%s: device's power status is %u:", __func__, getStatus);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetPowerStatus002
  * @tc.desc: get device power status test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetPowerStatus002, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] GetPowerStatus002 enter", __func__);
    int32_t ret;
    uint32_t getStatus = 0;
    /* Device "5" is used for testing nonexistent device node */
    ret = g_inputInterfaces->GetPowerStatus(INVALID_INDEX, getStatus);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device %d's power status failed, ret %d", __func__, INVALID_INDEX, ret);
    }

    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetVendorName001
  * @tc.desc: get device vendor name test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetVendorName001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] GetVendorName001 enter", __func__);
    int32_t ret;
    std::string vendorName;

    ret = g_inputInterfaces->GetVendorName(TOUCH_INDEX, vendorName);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device's vendor name failed, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    HDF_LOGI("%s: device's vendor name is %s:", __func__, vendorName.c_str());
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetVendorName002
  * @tc.desc: get device vendor name test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetVendorName002, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] GetVendorName002 enter", __func__);
    int32_t ret;
    std::string vendorName;
    /* Device "5" is used for testing nonexistent device node */
    ret = g_inputInterfaces->GetVendorName(INVALID_INDEX, vendorName);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device %d's vendor name failed, ret %d", __func__, INVALID_INDEX, ret);
    }

    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipName001
  * @tc.desc: get device chip name test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetChipName001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] GetChipName001 enter", __func__);
    int32_t ret;
    std::string chipName;

    ret = g_inputInterfaces->GetChipName(TOUCH_INDEX, chipName);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device's chip name failed, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    HDF_LOGI("%s: device's chip name is %s", __func__, chipName.c_str());
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipName002
  * @tc.desc: get device chip name test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, GetChipName002, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] GetChipName002 enter", __func__);
    int32_t ret;
    std::string chipName;
    /* Device "5" is used for testing nonexistent device node */
    ret = g_inputInterfaces->GetChipName(INVALID_INDEX, chipName);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device %d's chip name failed, ret %d", __func__, INVALID_INDEX, ret);
    }

    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetGestureMode001
  * @tc.desc: set device gesture mode test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, SetGestureMode001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] SetGestureMode001 enter", __func__);
    int32_t ret;
    uint32_t gestureMode = 1;

    ret = g_inputInterfaces->SetGestureMode(TOUCH_INDEX, gestureMode);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: set device's gestureMode failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetGestureMode002
  * @tc.desc: set device gesture mode test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, SetGestureMode002, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] SetGestureMode002 enter", __func__);
    int32_t ret;
    uint32_t gestureMode = 1;
    /* Device "5" is used for testing nonexistent device node */
    ret = g_inputInterfaces->SetGestureMode(INVALID_INDEX, gestureMode);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: set device %d's gestureMode failed, ret %d", __func__, INVALID_INDEX, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RunCapacitanceTest001
  * @tc.desc: run capacitanceTest test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, RunCapacitanceTest001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] RunCapacitanceTest001 enter", __func__);
    int32_t ret;
    std::string result;
    uint32_t testType = MMI_TEST;

    ret = g_inputInterfaces->RunCapacitanceTest(TOUCH_INDEX, testType, result, TEST_RESULT_LEN);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: run capacitanceTest failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RunExtraCommand001
  * @tc.desc: run extra command test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, RunExtraCommand001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] RunExtraCommand001 enter", __func__);
    int32_t ret;
    struct ExtraCmd extraCmd;
    extraCmd.cmdCode = "WakeUpMode";
    extraCmd.cmdValue = "Enable";

    ret = g_inputInterfaces->RunExtraCommand(TOUCH_INDEX, extraCmd);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: run extraCommand failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RegisterCallbackAndReportData001
  * @tc.desc: register callback and report data test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, RegisterCallbackAndReportData001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] RegisterCallbackAndReportData001 enter", __func__);
    int32_t ret;

    ret = g_inputInterfaces->RegisterReportCallback(TOUCH_INDEX, g_callback);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: register callback failed for device 1, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);
    printf("%s: wait 15s for testing, pls touch the panel now\n", __func__);
    printf("%s: The event data is as following:\n", __func__);
    OsalMSleep(KEEP_ALIVE_TIME_MS);
}

/**
  * @tc.name: UnregisterReportCallback001
  * @tc.desc: unregister reportCallback test
  * @tc.type: func
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, UnregisterReportCallback001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    HDF_LOGI("%s: [hdi-input] UnregisterReportCallback001 enter", __func__);
    int32_t ret;

    ret  = g_inputInterfaces->UnregisterReportCallback(TOUCH_INDEX);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: unregister callback failed for device, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);

    ret = g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: close device failed, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: HotPlugCallback001
  * @tc.desc: input device hot plug test
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(HdfInputHdiTest, HotPlugCallback001, TestSize.Level0)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }

    HDF_LOGI("%s: [hdi-input] HotPlugCallback001 enter", __func__);
    int32_t ret = INPUT_SUCCESS;
    std::vector<DevDesc> sta;

    ret = g_inputInterfaces->RegisterHotPlugCallback(g_hotplugCb);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: register hotplug callback failed for device manager, ret %d", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);
    OpenOnlineDev(sta);

    printf("%s: wait 15s for testing, pls hotplug now\n", __func__);
    printf("%s: The event data is as following:\n", __func__);
    OsalMSleep(KEEP_ALIVE_TIME_MS);

    CloseOnlineDev(sta);

    ret = g_inputInterfaces->UnregisterHotPlugCallback();
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: unregister hotplug callback failed for device manager, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}
