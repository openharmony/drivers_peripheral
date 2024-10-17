/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <hdf_log.h>
#include "osal_time.h"
#include "v1_0/iinput_interfaces.h"
#include "input_type.h"
#include "input_callback_impl.h"

using namespace OHOS::HDI::Input::V1_0;
using namespace testing::ext;

namespace {
sptr<IInputInterfaces> g_inputInterfaces = nullptr;
sptr<IInputCallback> g_callback = nullptr;
sptr<IInputCallback> g_hotplugCb = nullptr;
constexpr int32_t TOUCH_INDEX = 1;
constexpr int32_t MAX_DEVICES = 33;
constexpr int32_t INIT_DEFAULT_VALUE = 255;
constexpr int32_t TEST_RESULT_LEN = 32;
std::vector<DevDesc> g_sta;
} // namespace

class HdfInputHdiTestAdditional : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdfInputHdiTestAdditional::SetUpTestCase()
{
    g_inputInterfaces = IInputInterfaces::Get(true);
    if (g_inputInterfaces != nullptr) {
        g_callback = new InputCallbackImpl(g_inputInterfaces, nullptr);
        g_hotplugCb = new InputCallbackImpl(g_inputInterfaces, g_callback);
        g_inputInterfaces->ScanInputDevice(g_sta);
    }
}

void HdfInputHdiTestAdditional::TearDownTestCase() {}

void HdfInputHdiTestAdditional::SetUp() {}

void HdfInputHdiTestAdditional::TearDown() {}

static bool IsOnlineDev(uint32_t devIndex)
{
    bool ret = false;
    int32_t i = 0;
    for (i = 0; i < g_sta.size(); i++) {
        if (g_sta[i].devIndex == devIndex) {
            ret = true;
            break;
        }
    }
    return ret;
}

/**
 * @tc.number : SUB_Driver_Input_ScanInputDevice_0200
 * @tc.name   : testScanInputDevice001
 * @tc.desc   : Reliability of function(ScanInputDevice)
 */
HWTEST_F(HdfInputHdiTestAdditional, testScanInputDevice001, Function | MediumTest | Level1)
{
    std::vector<DevDesc> sta;
    int32_t ret = 0;
    int i = 0;
    for (i = 0; i < 1000; i++) {
        ret |= g_inputInterfaces->ScanInputDevice(sta);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_OpenInputDevice_0300
 * @tc.name   : testOpenInputDevice001
 * @tc.desc   : Reliability of function(OpenInputDevice)
 */
HWTEST_F(HdfInputHdiTestAdditional, testOpenInputDevice001, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    int i = 0;
    for (i = 0; i < 1000; i++) {
        ret |= g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
        g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_OpenInputDevice_0400
 * @tc.name   : testOpenInputDevice002
 * @tc.desc   : Test parameters(devIndex::0) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testOpenInputDevice002, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = 0;
    ret = g_inputInterfaces->OpenInputDevice(devIndex);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_OpenInputDevice_0500
 * @tc.name   : testOpenInputDevice003
 * @tc.desc   : Test input param(devIndex::1~32)
 */
HWTEST_F(HdfInputHdiTestAdditional, testOpenInputDevice003, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_OpenInputDevice_0600
 * @tc.name   : testOpenInputDevice004
 * @tc.desc   : Test parameters(devIndex::33) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testOpenInputDevice004, Function | MediumTest | Level2)
{
    int32_t ret = g_inputInterfaces->OpenInputDevice(MAX_DEVICES);
    g_inputInterfaces->CloseInputDevice(MAX_DEVICES);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_CloseInputDevice_0300
 * @tc.name   : testCloseInputDevice001
 * @tc.desc   : Reliability of function(CloseInputDevice)
 */
HWTEST_F(HdfInputHdiTestAdditional, testCloseInputDevice001, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    int i = 0;
    for (i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
        if (ret != INPUT_SUCCESS) {
            break;
        }
        ret |= g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_CloseInputDevice_0400
 * @tc.name   : testCloseInputDevice002
 * @tc.desc   : Test parameters(devIndex::0) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testCloseInputDevice002, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = 0;
    ret = g_inputInterfaces->CloseInputDevice(devIndex);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_CloseInputDevice_0500
 * @tc.name   : testCloseInputDevice003
 * @tc.desc   : Test input param(devIndex::1~32)
 */
HWTEST_F(HdfInputHdiTestAdditional, testCloseInputDevice003, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_CloseInputDevice_0600
 * @tc.name   : testCloseInputDevice004
 * @tc.desc   : Test parameters(devIndex::33) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testCloseInputDevice004, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    ret = g_inputInterfaces->CloseInputDevice(MAX_DEVICES);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetInputDevice_0300
 * @tc.name   : testGetInputDevice001
 * @tc.desc   : Reliability of function(GetInputDevice)
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetInputDevice001, Function | MediumTest | Level1)
{
    struct DeviceInfo devInfo;
    int32_t ret = 0;
    int i = 0;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    for (i = 0; i < 1000; i++) {
        ret |= g_inputInterfaces->GetInputDevice(TOUCH_INDEX, devInfo);
    }
    g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetInputDevice_0400
 * @tc.name   : testGetInputDevice002
 * @tc.desc   : Test parameters(devIndex::0) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetInputDevice002, Function | MediumTest | Level2)
{
    struct DeviceInfo devInfo;
    int32_t ret = 0;
    uint32_t devIndex = 0;
    ret = g_inputInterfaces->GetInputDevice(devIndex, devInfo);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetInputDevice_0500
 * @tc.name   : testGetInputDevice003
 * @tc.desc   : Test input param(devIndex::1~32)
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetInputDevice003, Function | MediumTest | Level1)
{
    struct DeviceInfo devInfo;
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->GetInputDevice(devIndex, devInfo);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            g_inputInterfaces->CloseInputDevice(devIndex);
        } else {
            ret = g_inputInterfaces->GetInputDevice(devIndex, devInfo);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_GetInputDevice_0600
 * @tc.name   : testGetInputDevice004
 * @tc.desc   : Test parameters(devIndex::33) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetInputDevice004, Function | MediumTest | Level2)
{
    struct DeviceInfo devInfo;
    int32_t ret = g_inputInterfaces->GetInputDevice(MAX_DEVICES, devInfo);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetInputDeviceList_0200
 * @tc.name   : testGetInputDeviceList001
 * @tc.desc   : Reliability of function(GetInputDeviceList)
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetInputDeviceList001, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    int i = 0;
    uint32_t num = 0;
    std::vector<DeviceInfo> dev;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    for (i = 0; i < 1000; i++) {
        g_inputInterfaces->GetInputDeviceList(num, dev, MAX_INPUT_DEV_NUM);
    }
    g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 *
 * @tc.number : SUB_Driver_Input_SetPowerStatus_0500
 * @tc.name   : testSetPowerStatus001
 * @tc.desc   : Reliability of function(SetPowerStatus)
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetPowerStatus001, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    int i = 0;
    uint32_t setStatus = INPUT_SUSPEND;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    for (i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->SetPowerStatus(TOUCH_INDEX, setStatus);
    }
    g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetPowerStatus_0600
 * @tc.name   : testSetPowerStatus002
 * @tc.desc   : Test parameters(devIndex::0) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetPowerStatus002, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = 0;
    uint32_t setStatus = INPUT_SUSPEND;
    ret = g_inputInterfaces->SetPowerStatus(devIndex, setStatus);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetPowerStatus_0700
 * @tc.name   : testSetPowerStatus003
 * @tc.desc   : Test input param(devIndex::1~32)
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetPowerStatus003, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t setStatus = INPUT_SUSPEND;
    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->SetPowerStatus(devIndex, setStatus);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            g_inputInterfaces->CloseInputDevice(devIndex);
        } else {
            ret = g_inputInterfaces->SetPowerStatus(devIndex, setStatus);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_SetPowerStatus_0800
 * @tc.name   : testSetPowerStatus004
 * @tc.desc   : Test parameters(devIndex::33) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetPowerStatus004, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t setStatus = INPUT_SUSPEND;
    ret = g_inputInterfaces->SetPowerStatus(MAX_DEVICES, setStatus);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetPowerStatus_0900
 * @tc.name   : testSetPowerStatus005
 * @tc.desc   : Test parameters(devIndex::1,setStatus::INPUT_POWER_STATUS_UNKNOWN) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetPowerStatus005, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t setStatus = INPUT_POWER_STATUS_UNKNOWN;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->SetPowerStatus(TOUCH_INDEX, setStatus);
    g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetPowerStatus_1000
 * @tc.name   : testSetPowerStatus006
 * @tc.desc   : Test parameters(devIndex::33) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetPowerStatus006, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t setStatus = INPUT_POWER_STATUS_UNKNOWN;
    ret = g_inputInterfaces->SetPowerStatus(MAX_DEVICES, setStatus);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetPowerStatus_1100
 * @tc.name   : testSetPowerStatus007
 * @tc.desc   : Test parameters(devIndex::1,setStatus::5) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetPowerStatus007, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t setStatus = 5;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->SetPowerStatus(TOUCH_INDEX, setStatus);
    g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetPowerStatus_1200
 * @tc.name   : testSetPowerStatus008
 * @tc.desc   : Test parameters(devIndex::1,setStatus::0x7fffffff) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetPowerStatus008, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t setStatus = 0x7fffffff;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->SetPowerStatus(TOUCH_INDEX, setStatus);
    g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetPowerStatus_0300
 * @tc.name   : testGetPowerStatus001
 * @tc.desc   : Reliability of function(GetPowerStatus)
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetPowerStatus001, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    int i = 0;
    uint32_t getStatus = 0;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    for (i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->GetPowerStatus(TOUCH_INDEX, getStatus);
    }
    g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetPowerStatus_0400
 * @tc.name   : testGetPowerStatus002
 * @tc.desc   : Test parameters(devIndex::0) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetPowerStatus002, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = 0;
    uint32_t getStatus = 0;
    ret = g_inputInterfaces->GetPowerStatus(devIndex, getStatus);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetPowerStatus_0600
 * @tc.name   : testGetPowerStatus004
 * @tc.desc   : Test input param(devIndex::3~32)
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetPowerStatus004, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = 3;
    uint32_t getStatus = 0;
    for (devIndex = 3; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->GetPowerStatus(devIndex, getStatus);
            g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->GetPowerStatus(devIndex, getStatus);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_GetPowerStatus_0700
 * @tc.name   : testGetPowerStatus005
 * @tc.desc   : Test parameters(devIndex::33) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetPowerStatus005, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t getStatus = 0;
    ret = g_inputInterfaces->GetPowerStatus(MAX_DEVICES, getStatus);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetDeviceType_0300
 * @tc.name   : testGetDeviceType001
 * @tc.desc   : Reliability of function(GetDeviceType)
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetDeviceType001, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    int i = 0;
    uint32_t devType = INIT_DEFAULT_VALUE;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    for (i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->GetDeviceType(TOUCH_INDEX, devType);
    }
    g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetDeviceType_0400
 * @tc.name   : testGetDeviceType002
 * @tc.desc   : Test parameters(devIndex::0) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetDeviceType002, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = 0;
    uint32_t devType = INIT_DEFAULT_VALUE;
    ret = g_inputInterfaces->GetDeviceType(devIndex, devType);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetDeviceType_0500
 * @tc.name   : testGetDeviceType003
 * @tc.desc   : Test input param(devIndex::1~32)
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetDeviceType003, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t devType = INIT_DEFAULT_VALUE;
    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->GetDeviceType(devIndex, devType);
            g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->GetDeviceType(devIndex, devType);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_GetDeviceType_0600
 * @tc.name   : testGetDeviceType004
 * @tc.desc   : Test parameters(devIndex::33) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetDeviceType004, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devType = INIT_DEFAULT_VALUE;
    ret = g_inputInterfaces->GetDeviceType(MAX_DEVICES, devType);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetGestureMode_0300
 * @tc.name   : testSetGestureMode001
 * @tc.desc   : Reliability of function(SetGestureMode)
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetGestureMode001, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t gestureMode = 1;
    int i = 0;
    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    for (i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->SetGestureMode(TOUCH_INDEX, gestureMode);
    }
    g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetGestureMode_0400
 * @tc.name   : testSetGestureMode002
 * @tc.desc   : Test parameters(devIndex::0) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetGestureMode002, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = 0;
    uint32_t gestureMode = 1;
    ret = g_inputInterfaces->SetGestureMode(devIndex, gestureMode);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetGestureMode_0500
 * @tc.name   : testSetGestureMode003
 * @tc.desc   : Test input param(devIndex::1~32)
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetGestureMode003, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t gestureMode = 1;
    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->SetGestureMode(devIndex, gestureMode);
            g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->SetGestureMode(devIndex, gestureMode);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_SetGestureMode_0600
 * @tc.name   : testSetGestureMode004
 * @tc.desc   : Test parameters(devIndex::33) with abnormal input
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetGestureMode004, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t gestureMode = 1;
    ret = g_inputInterfaces->SetGestureMode(MAX_DEVICES, gestureMode);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetGestureMode_0700
 * @tc.name   : testSetGestureMode005
 * @tc.desc   : Test input param(devIndex::1,gestureMode::0)
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetGestureMode005, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t gestureMode = 0;
    g_inputInterfaces->OpenInputDevice(devIndex);
    ret = g_inputInterfaces->SetGestureMode(devIndex, gestureMode);
    g_inputInterfaces->CloseInputDevice(devIndex);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_SetGestureMode_0800
 * @tc.name   : testSetGestureMode006
 * @tc.desc   : Test input param(devIndex::1,gestureMode::0x7fffffff)
 */
HWTEST_F(HdfInputHdiTestAdditional, testSetGestureMode006, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t gestureMode = 0x7fffffff;
    g_inputInterfaces->OpenInputDevice(devIndex);
    ret = g_inputInterfaces->SetGestureMode(devIndex, gestureMode);
    g_inputInterfaces->CloseInputDevice(devIndex);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetChipInfo_0300
 * @tc.name   : testGetChipInfo001
 * @tc.desc   : GetChipInfo, stability test
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetChipInfo001, Function | MediumTest | Level1)
{
    int32_t ret;

    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);

    std::string chipInfo;

    for (int i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->GetChipInfo(TOUCH_INDEX, chipInfo);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    }

    ret = g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetChipInfo_0400
 * @tc.name   : testGetChipInfo002
 * @tc.desc   : GetChipInfo, Test input param, devIndex = 0
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetChipInfo002, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = 0;
    std::string chipInfo;

    ret = g_inputInterfaces->GetChipInfo(devIndex, chipInfo);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetChipInfo_0500
 * @tc.name   : testGetChipInfo003
 * @tc.desc   : GetChipInfo, Test input param
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetChipInfo003, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    std::string chipInfo;

    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->GetChipInfo(devIndex, chipInfo);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->GetChipInfo(devIndex, chipInfo);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_GetChipInfo_0600
 * @tc.name   : testGetChipInfo004
 * @tc.desc   : GetChipInfo, Test input param, devIndex = 32
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetChipInfo004, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = MAX_DEVICES;
    std::string chipInfo;

    ret = g_inputInterfaces->GetChipInfo(devIndex, chipInfo);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetVendorName_0300
 * @tc.name   : testGetVendorName001
 * @tc.desc   : GetVendorName, stability test
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetVendorName001, Function | MediumTest | Level1)
{
    int32_t ret;

    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);

    std::string vendorName;

    for (int i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->GetVendorName(TOUCH_INDEX, vendorName);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    }

    ret = g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetVendorName_0400
 * @tc.name   : testGetVendorName002
 * @tc.desc   : GetVendorName, Test input param, devIndex = 0
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetVendorName002, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = 0;
    std::string vendorName;

    ret = g_inputInterfaces->GetVendorName(devIndex, vendorName);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetVendorName_0500
 * @tc.name   : testGetVendorName003
 * @tc.desc   : GetVendorName, Test input param, devIndex = 2
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetVendorName003, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    std::string vendorName;

    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->GetVendorName(devIndex, vendorName);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->GetVendorName(devIndex, vendorName);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_GetVendorName_0600
 * @tc.name   : testGetVendorName004
 * @tc.desc   : GetVendorName, Test input param, devIndex = 32
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetVendorName004, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = MAX_DEVICES;
    std::string vendorName;

    ret = g_inputInterfaces->GetVendorName(devIndex, vendorName);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetChipName_0300
 * @tc.name   : testGetChipName001
 * @tc.desc   : GetChipName, stability test
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetChipName001, Function | MediumTest | Level1)
{
    int32_t ret;

    ret = g_inputInterfaces->OpenInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);

    std::string chipName;

    for (int i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->GetChipName(TOUCH_INDEX, chipName);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    }

    ret = g_inputInterfaces->CloseInputDevice(TOUCH_INDEX);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetChipName_0400
 * @tc.name   : testGetChipName002
 * @tc.desc   : GetChipName, Test input param, devIndex = 0
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetChipName002, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = 0;
    std::string chipName;

    ret = g_inputInterfaces->GetChipName(devIndex, chipName);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_GetChipName_0500
 * @tc.name   : testGetChipName003
 * @tc.desc   : GetChipName, Test input param, devIndex = 2
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetChipName003, Function | MediumTest | Level1)
{
    int32_t ret = 0;
    uint32_t devIndex = TOUCH_INDEX;
    std::string chipName;

    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->GetChipName(devIndex, chipName);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->GetChipName(devIndex, chipName);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_GetChipName_0600
 * @tc.name   : testGetChipName004
 * @tc.desc   : GetChipName, Test input param, devIndex = 32
 */
HWTEST_F(HdfInputHdiTestAdditional, testGetChipName004, Function | MediumTest | Level2)
{
    int32_t ret = 0;
    uint32_t devIndex = MAX_DEVICES;
    std::string chipName;

    ret = g_inputInterfaces->GetChipName(devIndex, chipName);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_0600
 * @tc.name   : testRunCapacitanceTest001
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 0 and testType is BASE_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest001, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = 0;
    uint32_t testType = BASE_TEST;
    std::string result;
    ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_0700
 * @tc.name   : testRunCapacitanceTest002
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 3-31 and testType is
 * BASE_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest002, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t testType = BASE_TEST;
    std::string result;
    for (devIndex = 3; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_0800
 * @tc.name   : testRunCapacitanceTest003
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 32 and testType is BASE_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest003, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = MAX_DEVICES;
    uint32_t testType = BASE_TEST;
    std::string result;
    ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_0900
 * @tc.name   : testRunCapacitanceTest004
 * @tc.desc   : Verify the stability of the RunCapacitanceTest function when devIndex is 1 and testType is BASE_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest004, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t testType = BASE_TEST;
    std::string result;
    for (int32_t i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->OpenInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->CloseInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_1000
 * @tc.name   : testRunCapacitanceTest005
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 0 and testType is FULL_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest005, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = 0;
    uint32_t testType = FULL_TEST;
    std::string result;
    ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_1100
 * @tc.name   : testRunCapacitanceTest006
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 3-31 and testType is
 * FULL_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest006, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t testType = FULL_TEST;
    std::string result;
    for (devIndex = 3; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_1200
 * @tc.name   : testRunCapacitanceTest007
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 32 and testType is FULL_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest007, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = MAX_DEVICES;
    uint32_t testType = FULL_TEST;
    std::string result;
    ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_1300
 * @tc.name   : testRunCapacitanceTest008
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 0 and testType is MMI_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest008, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = 0;
    uint32_t testType = MMI_TEST;
    std::string result;
    ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_1400
 * @tc.name   : testRunCapacitanceTest009
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 3-31 and testType is
 * MMI_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest009, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t testType = MMI_TEST;
    std::string result;
    for (devIndex = 3; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_1500
 * @tc.name   : testRunCapacitanceTest010
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 32 and testType is MMI_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest010, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = MAX_DEVICES;
    uint32_t testType = MMI_TEST;
    std::string result;
    ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_1600
 * @tc.name   : testRunCapacitanceTest011
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 0 and testType is
 * RUNNING_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest011, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = 0;
    uint32_t testType = RUNNING_TEST;
    std::string result;
    ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_1700
 * @tc.name   : testRunCapacitanceTest012
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 3-31 and testType is
 * RUNNING_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest012, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t testType = RUNNING_TEST;
    std::string result;
    for (devIndex = 3; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_1800
 * @tc.name   : testRunCapacitanceTest013
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 32 and testType is
 * RUNNING_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest013, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = MAX_DEVICES;
    uint32_t testType = RUNNING_TEST;
    std::string result;
    ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_1900
 * @tc.name   : testRunCapacitanceTest014
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 1 and testType is
 * BASE_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest014, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t testType = BASE_TEST;
    std::string result;
    if (IsOnlineDev(devIndex)) {
        ret = g_inputInterfaces->OpenInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->CloseInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    } else {
        ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
        EXPECT_NE(ret, INPUT_SUCCESS);
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_2100
 * @tc.name   : testRunCapacitanceTest016
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 1 and testType is
 * FULL_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest016, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t testType = FULL_TEST;
    std::string result;
    if (IsOnlineDev(devIndex)) {
        ret = g_inputInterfaces->OpenInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->CloseInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    } else {
        ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
        EXPECT_NE(ret, INPUT_SUCCESS);
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_2300
 * @tc.name   : testRunCapacitanceTest018
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 1 and testType is
 * MMI_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest018, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t testType = MMI_TEST;
    std::string result;
    if (IsOnlineDev(devIndex)) {
        ret = g_inputInterfaces->OpenInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->CloseInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    } else {
        ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
        EXPECT_NE(ret, INPUT_SUCCESS);
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunCapacitanceTest_2500
 * @tc.name   : testRunCapacitanceTest020
 * @tc.desc   : Verify the reliability of the RunCapacitanceTest function when devIndex is 1 and testType is
 * RUNNING_TEST.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunCapacitanceTest020, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    uint32_t testType = RUNNING_TEST;
    std::string result;
    if (IsOnlineDev(devIndex)) {
        ret = g_inputInterfaces->OpenInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->CloseInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    } else {
        ret = g_inputInterfaces->RunCapacitanceTest(devIndex, testType, result, TEST_RESULT_LEN);
        EXPECT_NE(ret, INPUT_SUCCESS);
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunExtraCommand_0300
 * @tc.name   : testRunExtraCommand001
 * @tc.desc   : Verify the reliability of the RunExtraCommand function when devIndex is 0.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunExtraCommand001, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = 0;
    struct ExtraCmd extraCmd;
    extraCmd.cmdCode = "WakeUpMode";
    extraCmd.cmdValue = "Enable";
    ret = g_inputInterfaces->RunExtraCommand(devIndex, extraCmd);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunExtraCommand_0400
 * @tc.name   : testRunExtraCommand002
 * @tc.desc   : Verify the reliability of the RunExtraCommand function when devIndex is 2.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunExtraCommand002, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    struct ExtraCmd extraCmd;
    extraCmd.cmdCode = "WakeUpMode";
    extraCmd.cmdValue = "Enable";
    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->RunExtraCommand(devIndex, extraCmd);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->RunExtraCommand(devIndex, extraCmd);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunExtraCommand_0500
 * @tc.name   : testRunExtraCommand003
 * @tc.desc   : Verify the reliability of the RunExtraCommand function when devIndex is 32.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunExtraCommand003, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = MAX_DEVICES;
    struct ExtraCmd extraCmd;
    extraCmd.cmdCode = "WakeUpMode";
    extraCmd.cmdValue = "Enable";
    ret = g_inputInterfaces->RunExtraCommand(devIndex, extraCmd);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunExtraCommand_0600
 * @tc.name   : testRunExtraCommand004
 * @tc.desc   : Verify the stability of the RunExtraCommand function when devIndex is 1.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunExtraCommand004, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    struct ExtraCmd extraCmd;
    extraCmd.cmdCode = "WakeUpMode";
    extraCmd.cmdValue = "Enable";
    for (int32_t i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->OpenInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->RunExtraCommand(devIndex, extraCmd);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->CloseInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    }
}

/**
 * @tc.number : SUB_Driver_Input_RunExtraCommand_0700
 * @tc.name   : testRunExtraCommand005
 * @tc.desc   : Verify the reliability of the RunExtraCommand function when devIndex is 1.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunExtraCommand005, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    struct ExtraCmd extraCmd;
    extraCmd.cmdCode = "";
    extraCmd.cmdValue = "";
    ret = g_inputInterfaces->OpenInputDevice(devIndex);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->RunExtraCommand(devIndex, extraCmd);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->CloseInputDevice(devIndex);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunExtraCommand_0800
 * @tc.name   : testRunExtraCommand006
 * @tc.desc   : Verify the reliability of the RunExtraCommand function when devIndex is 1.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunExtraCommand006, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    struct ExtraCmd extraCmd;
    extraCmd.cmdCode = "";
    extraCmd.cmdValue = "Enable";
    ret = g_inputInterfaces->OpenInputDevice(devIndex);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->RunExtraCommand(devIndex, extraCmd);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->CloseInputDevice(devIndex);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RunExtraCommand_0900
 * @tc.name   : testRunExtraCommand007
 * @tc.desc   : Verify the reliability of the RunExtraCommand function when devIndex is 1.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRunExtraCommand007, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    struct ExtraCmd extraCmd;
    extraCmd.cmdCode = "WakeUpMode";
    extraCmd.cmdValue = "";
    ret = g_inputInterfaces->OpenInputDevice(devIndex);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->RunExtraCommand(devIndex, extraCmd);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->CloseInputDevice(devIndex);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RegisterReportCallback_0300
 * @tc.name   : testRegisterReportCallback001
 * @tc.desc   : Verify the reliability of the RegisterReportCallback function when devIndex is 0.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRegisterReportCallback001, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = 0;
    ret = g_inputInterfaces->RegisterReportCallback(devIndex, g_callback);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RegisterReportCallback_0400
 * @tc.name   : testRegisterReportCallback002
 * @tc.desc   : Verify the reliability of the RegisterReportCallback function when devIndex is 1-31.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRegisterReportCallback002, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    for (devIndex = TOUCH_INDEX; devIndex < MAX_DEVICES; devIndex++) {
        if (IsOnlineDev(devIndex)) {
            ret = g_inputInterfaces->OpenInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->RegisterReportCallback(devIndex, g_callback);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->UnregisterReportCallback(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
            ret = g_inputInterfaces->CloseInputDevice(devIndex);
            EXPECT_EQ(ret, INPUT_SUCCESS);
        } else {
            ret = g_inputInterfaces->RegisterReportCallback(devIndex, g_callback);
            EXPECT_NE(ret, INPUT_SUCCESS);
        }
    }
}

/**
 * @tc.number : SUB_Driver_Input_RegisterReportCallback_0500
 * @tc.name   : testRegisterReportCallback003
 * @tc.desc   : Verify the reliability of the RegisterReportCallback function when devIndex is 32.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRegisterReportCallback003, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = MAX_DEVICES;
    ret = g_inputInterfaces->RegisterReportCallback(devIndex, g_callback);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RegisterReportCallback_0600
 * @tc.name   : testRegisterReportCallback004
 * @tc.desc   : Verify the stability of the RegisterReportCallback function when devIndex is 1.
 */
HWTEST_F(HdfInputHdiTestAdditional, testRegisterReportCallback004, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    for (int32_t i = 0; i < 1000; i++) {
        ret = g_inputInterfaces->OpenInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->RegisterReportCallback(devIndex, g_callback);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->UnregisterReportCallback(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->CloseInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    }
}

/**
 * @tc.number : SUB_Driver_Input_UnregisterReportCallback_0200
 * @tc.name   : testUnregisterReportCallback001
 * @tc.desc   : Verify the reliability of the UnregisterReportCallback function when devIndex is 1.
 */
HWTEST_F(HdfInputHdiTestAdditional, testUnregisterReportCallback001, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    uint32_t devIndex = TOUCH_INDEX;
    if (IsOnlineDev(devIndex)) {
        ret = g_inputInterfaces->OpenInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->RegisterReportCallback(devIndex, g_callback);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->UnregisterReportCallback(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
        ret = g_inputInterfaces->CloseInputDevice(devIndex);
        EXPECT_EQ(ret, INPUT_SUCCESS);
    } else {
        ret = g_inputInterfaces->UnregisterReportCallback(devIndex);
        EXPECT_NE(ret, INPUT_SUCCESS);
    }
}

/**
 * @tc.number : SUB_Driver_Input_RegisterHotPlugCallback_0100
 * @tc.name   : testRegisterHotPlugCallback001
 * @tc.desc   : Validation function RegisterHotPlugCallback results in success.
 * when the hotPlugCallback parameter is g_callback
 */
HWTEST_F(HdfInputHdiTestAdditional, testRegisterHotPlugCallback001, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    ret = g_inputInterfaces->RegisterHotPlugCallback(g_callback);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterfaces->UnregisterHotPlugCallback();
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_RegisterHotPlugCallback_0200
 * @tc.name   : testRegisterHotPlugCallback002
 * @tc.desc   : Validation function RegisterHotPlugCallback results in success.
 * when the hotPlugCallback parameter is nullptr
 */
HWTEST_F(HdfInputHdiTestAdditional, testRegisterHotPlugCallback002, Function | MediumTest | Level2)
{
    int32_t ret = INPUT_SUCCESS;
    ret = g_inputInterfaces->RegisterHotPlugCallback(nullptr);
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
 * @tc.number : SUB_Driver_Input_UnregisterHotPlugCallback_0100
 * @tc.name   : testUnregisterHotPlugCallback001
 * @tc.desc   : Verify the reliability of UnregisterHotPlugCallback function and functional
 */
HWTEST_F(HdfInputHdiTestAdditional, testUnregisterHotPlugCallback001, Function | MediumTest | Level1)
{
    int32_t ret = INPUT_SUCCESS;
    ret = g_inputInterfaces->UnregisterHotPlugCallback();
    EXPECT_EQ(ret, INPUT_SUCCESS);
}
