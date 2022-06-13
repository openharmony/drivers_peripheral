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
#include "hdf_base.h"
#include "osal_time.h"
#include "v1_0/iinput_interfaces.h"
#include "input_type.h"
#include "input_callback_impl.h"

using namespace OHOS::HDI::Input::V1_0;
using namespace testing::ext;

namespace {
    sptr<IInputInterfaces>  g_inputInterfaces = nullptr;
    const sptr<IInputCallback> g_callback = new InputCallbackImpl();
    const sptr<IInputCallback> g_hotplugCb = new InputCallbackImpl();

    constexpr int32_t INIT_DEFAULT_VALUE = 255;
    constexpr int32_t KEEP_ALIVE_TIME_MS = 15000;
    constexpr int32_t TOUCH_INDEX = 1;
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
    g_inputInterfaces = IInputInterfaces::Get();
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

/**
  * @tc.name: GetInputClient
  * @tc.desc: Get a client and check whether the client is empty.
  * @tc.type: func
  * @tc.require: #I4L3LF
  */
HWTEST_F(HdfInputHdiTest, GetInputClient001, TestSize.Level1)
{
    ASSERT_NE(nullptr, g_inputInterfaces);
}

HWTEST_F(HdfInputHdiTest, ScanInputDevice001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    std::vector<DevDesc> sta;

    printf("%s: [Hdi-Input] ScanInputDevice enter\n", __func__);
    int32_t ret;

    ret  = g_inputInterfaces->ScanInputDevice(sta);
    if (ret == INPUT_SUCCESS) {
        printf("%s: %d, %d, %d, %d\n", __func__, sta[0].devType, sta[0].devIndex, sta[1].devType, sta[1].devIndex);
    }

    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: OpenInputDev001
  * @tc.desc: open input device test
  * @tc.type: func
  * @tc.require: AR000F867R, AR000F8QNL
  */
HWTEST_F(HdfInputHdiTest, OpenInputDevice001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [Hdi-Input] OpenInputDevice enter\n", __func__);

    int32_t ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    if (ret != INPUT_SUCCESS) {
        printf("%s: open device failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: CloseInputDevice001
  * @tc.desc: close input device test
  * @tc.type: func
  * @tc.require: AR000F867T, AR000F8QNL
  */
HWTEST_F(HdfInputHdiTest, CloseInputDevice001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] CloseInputDevice enter\n", __func__);

    int32_t ret = g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    if (ret != INPUT_SUCCESS) {
        printf("%s: close device failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetInputDevice001
  * @tc.desc: get input device info test
  * @tc.type: func
  * @tc.require: AR000F867S
  */
HWTEST_F(HdfInputHdiTest, GetInputDevice001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] GetInputDevice enter\n", __func__);
    struct DeviceInfo dev;

    int32_t ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    if (ret != INPUT_SUCCESS) {
        printf("%s: open device failed, ret %d\n", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    ret = g_inputInterfaces->GetInputDevice(TOUCH_INDEX, dev);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device failed, ret %d\n", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    printf("%s: devindex = %u, devType = %u\n", __func__, dev.devIndex,
            dev.devType);
    printf("%s: chipInfo = %s, vendorName = %s, chipName = %s\n",
        __func__, dev.chipInfo.c_str(), dev.vendorName.c_str(), dev.chipName.c_str());
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetInputDeviceList001
  * @tc.desc: get input device list info test
  * @tc.type: func
  * @tc.require: AR000F8680
  */
HWTEST_F(HdfInputHdiTest, GetInputDeviceList001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] GetInputDeviceList enter\n", __func__);
    int32_t ret;
    uint32_t num = 0;
    std::vector<DeviceInfo> dev;

    ret = g_inputInterfaces->GetInputDeviceList(num, dev, MAX_INPUT_DEV_NUM);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device list failed, ret %d\n", __func__, ret);
    }
    ret = num <= MAX_INPUT_DEV_NUM ? HDF_SUCCESS : HDF_FAILURE;  /* num <= MAX_INPUT_DEV_NUM return true */
    ASSERT_EQ(ret, HDF_SUCCESS);


    for (uint32_t i = 0; i < num; i++) {
        printf("%s: num = %u, device[%u]'s info is:\n", __func__, num, i);
        printf("%s: index = %u, devType = %u\n", __func__, dev[i].devIndex,
                dev[i].devType);
        printf("%s: chipInfo = %s, vendorName = %s, chipName = %s\n",
            __func__, dev[i].chipInfo.c_str(), dev[i].vendorName.c_str(), dev[i].chipName.c_str());
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetDeviceType001
  * @tc.desc: get input device type test
  * @tc.type: func
  * @tc.require: AR000F8681, AR000F8QNL
  */
HWTEST_F(HdfInputHdiTest, GetDeviceType001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] GetDeviceType enter\n", __func__);
    int32_t ret;
    uint32_t devType = INIT_DEFAULT_VALUE;

    ret = g_inputInterfaces->GetDeviceType(TOUCH_INDEX, devType);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device's type failed, ret %d\n", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    printf("%s: device's type is %u\n", __func__, devType);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipInfo001
  * @tc.desc: get input device chip info test
  * @tc.type: func
  * @tc.require: AR000F8682
  */
HWTEST_F(HdfInputHdiTest, GetChipInfo001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] GetChipInformation enter\n", __func__);
    int32_t ret;
    std::string chipInfo;

    ret = g_inputInterfaces->GetChipInfo(TOUCH_INDEX, chipInfo);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device's chip info failed, ret %d\n", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    printf("%s: device's chip info is %s\n", __func__, chipInfo.c_str());
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetPowerStatus001
  * @tc.desc: set device power status test
  * @tc.type: func
  * @tc.require: AR000F867T
  */
HWTEST_F(HdfInputHdiTest, SetPowerStatus001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] SetPowerStatus enter\n", __func__);
    int32_t ret;
    uint32_t setStatus = INPUT_LOW_POWER;

    ret = g_inputInterfaces->SetPowerStatus(TOUCH_INDEX, setStatus);
    if (ret != INPUT_SUCCESS) {
        printf("%s: set device's power status failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetPowerStatus001
  * @tc.desc: get device power status test
  * @tc.type: func
  * @tc.require: AR000F867S
  */
HWTEST_F(HdfInputHdiTest, GetPowerStatus001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] GetPowerStatus enter\n", __func__);
    int32_t ret;
    uint32_t getStatus = 0;

    ret = g_inputInterfaces->GetPowerStatus(TOUCH_INDEX, getStatus);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device's power status failed, ret %d\n", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    printf("%s: device's power status is %u:\n", __func__, getStatus);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetVendorName001
  * @tc.desc: get device vendor name test
  * @tc.type: func
  * @tc.require: AR000F867T
  */
HWTEST_F(HdfInputHdiTest, GetVendorName001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] GetVendorName enter\n", __func__);
    int32_t ret;
    std::string vendorName;

    ret = g_inputInterfaces->GetVendorName(TOUCH_INDEX, vendorName);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device's vendor name failed, ret %d\n", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    printf("%s: device's vendor name is %s:\n", __func__, vendorName.c_str());
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipName001
  * @tc.desc: get device chip name test
  * @tc.type: func
  * @tc.require: AR000F867S
  */
HWTEST_F(HdfInputHdiTest, GetChipName001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] GetChipName enter\n", __func__);
    int32_t ret;
    std::string chipName;

    ret = g_inputInterfaces->GetChipName(TOUCH_INDEX, chipName);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device's chip name failed, ret %d\n", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);

    printf("%s: device's chip name is %s\n", __func__, chipName.c_str());
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetGestureMode001
  * @tc.desc: set device gesture mode test
  * @tc.type: func
  * @tc.require: AR000F867S
  */
HWTEST_F(HdfInputHdiTest, SetGestureMode001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] SetGestureMode enter\n", __func__);
    int32_t ret;
    uint32_t gestureMode = 1;

    ret = g_inputInterfaces->SetGestureMode(TOUCH_INDEX, gestureMode);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device's gestureMode failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RegisterCallbackAndReportData001
  * @tc.desc: get input device chip info test
  * @tc.type: func
  * @tc.require: AR000F8682, AR000F8QNL
  */
HWTEST_F(HdfInputHdiTest, RegisterCallbackAndReportData001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] RegisterCallbackAndReportData enter\n", __func__);
    int32_t ret;

    ret = g_inputInterfaces->RegisterReportCallback(TOUCH_INDEX, g_callback);
    if (ret != INPUT_SUCCESS) {
        printf("%s: register callback failed for device 1, ret %d\n", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);
    printf("%s: wait 15s for testing, pls touch the panel now\n", __func__);
    printf("%s: The event data is as following:\n", __func__);
    OsalMSleep(KEEP_ALIVE_TIME_MS);
}

/**
  * @tc.name: UnregisterReportCallback001
  * @tc.desc: get input device chip info test
  * @tc.type: func
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdfInputHdiTest, UnregisterReportCallback001, TestSize.Level1)
{
    if (g_inputInterfaces == nullptr) {
        ASSERT_NE(nullptr, g_inputInterfaces);
        return;
    }
    printf("%s: [hdi-input] UnregisterReportCallback enter\n", __func__);
    int32_t ret;

    ret  = g_inputInterfaces->UnregisterReportCallback(TOUCH_INDEX);
    if (ret != INPUT_SUCCESS) {
        printf("%s: unregister callback failed for device, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);

    ret = g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    if (ret != INPUT_SUCCESS) {
        printf("%s: close device failed, ret %d\n", __func__, ret);
    }
    ASSERT_EQ(ret, INPUT_SUCCESS);
    printf("%s: Close the device successfully after all test\n", __func__);
}
