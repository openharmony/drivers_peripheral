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
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <string>
#include <unistd.h>
#include "input_device_manager.h"
#include "input_manager.h"
#include "osal_time.h"
#include "osal_mem.h"
#include "input_uhdf_log.h"

using namespace testing::ext;
using namespace OHOS::Input;
static IInputInterface *g_inputInterface;
static InputEventCb g_callback;
static InputHostCb g_hotplugCb;
static int32_t g_touchIndex;
static uint32_t g_index = 1;
static int32_t g_fileDescriptorFirst = 3;
static int32_t g_fileDescriptorSecond = 4;
static uint32_t g_type = INDEV_TYPE_MOUSE;
static const int32_t KEEP_ALIVE_TIME_MS = 3000;
static const int32_t INVALID_INDEX = 15;
static const int32_t INVALID_INDEX1 = -1;
static const int32_t MAX_DEVICES = 32;
static const int32_t TEST_RESULT_LEN = 32;
static const int32_t TEST_TYPE = 2;
static const int32_t TEST_LEN1 = 10;
static const int32_t TEST_LEN2 = -1;
static const int32_t VALUE_NULL = 0;
static const int32_t VALUE_DEFAULT = 1;
static const uint32_t INIT_DEFAULT_VALUE = 255;
static const uint32_t STATUS = INPUT_DEVICE_STATUS_CLOSED;
static const string NODE_PATH = "dev/input/";
static const size_t COUNT = 1;
static const size_t INVALID_DEV_INDEX = 33;

namespace {
std::string g_errLog;
void MyLogCallback(const LogType type, const LogLevel level, const unsigned int domain, const char *tag,
    const char *msg)
{
    g_errLog = msg;
}
}

class HdiInputTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HdiInputTest::SetUpTestCase()
{
    int32_t ret = GetInputInterface(&g_inputInterface);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get input hdi failed, ret %d\n", __func__, ret);
    }
}

void HdiInputTest::TearDownTestCase()
{
    ReleaseInputInterface(&g_inputInterface);
}

void HdiInputTest::SetUp()
{
}

void HdiInputTest::TearDown()
{
}

#define INPUT_CHECK_NULL_POINTER(pointer, ret) do { \
    if ((pointer) == nullptr) { \
        printf("%s: null pointer", __func__); \
        ASSERT_EQ ((ret), INPUT_SUCCESS); \
    } \
} while (0)

static void ReportEventPkgCallback(const InputEventPackage **pkgs, uint32_t count, uint32_t devIndex)
{
    if (pkgs == nullptr) {
        printf("%s: pkgs is null\n", __func__);
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        printf("device action Index: %u devIndex: %u type: %u code: %u value %d\n",
            i, devIndex, pkgs[i]->type, pkgs[i]->code, pkgs[i]->value);
    }
}

static void ReportHotPlugEventPkgCallback(const InputHotPlugEvent *msg)
{
    if (msg == nullptr) {
        printf("%s: msg is null\n", __func__);
        return;
    }
    printf("%s: device hotplug action devIndex: %u devType: %u status: %u\n", __func__,
        msg->devIndex, msg->devType, msg->status);
    if (msg->status == INPUT_DEVICE_STATUS_OPENED) {
        EXPECT_EQ(g_inputInterface->iInputManager->OpenInputDevice(msg->devIndex), INPUT_SUCCESS);
    } else if (msg->status == INPUT_DEVICE_STATUS_CLOSED) {
        EXPECT_EQ(g_inputInterface->iInputManager->CloseInputDevice(msg->devIndex), INPUT_SUCCESS);
    } else {
        // do nothing
    }
}

/**
  * @tc.name: ScanInputDevice001
  * @tc.desc: scan input device test
  * @tc.type: FUNC
  * @tc.require: AR000F867R
  */
HWTEST_F(HdiInputTest, ScanInputDevice001, TestSize.Level0)
{
    InputDevDesc sta[MAX_DEVICES];
    int32_t ret = memset_s(sta, MAX_DEVICES * sizeof(InputDevDesc), 0, MAX_DEVICES * sizeof(InputDevDesc));
    ASSERT_EQ(ret, EOK);
    printf("%s: [Input] ScanInputDevice001 enter %d\n", __func__, __LINE__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    ret  = g_inputInterface->iInputManager->ScanInputDevice(sta, sizeof(sta) / sizeof(InputDevDesc));
    if (ret == INPUT_SUCCESS) {
        printf("%s: ScanInputDevice result: %d, %d, %d, %d\n",
               __func__, sta[0].devType, sta[0].devIndex, sta[1].devType, sta[1].devIndex);
    }
    for (int32_t i = 1; i < MAX_DEVICES; i++) {
        if (sta[i].devIndex == 0) {
            break;
        }
        if (sta[i].devType == INDEV_TYPE_TOUCH) {
            g_touchIndex = sta[i].devIndex;
        }
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: OpenInputDevice001
  * @tc.desc: open input device test
  * @tc.type: FUNC
  * @tc.require: AR000F867R
  */
HWTEST_F(HdiInputTest, OpenInputDev001, TestSize.Level0)
{
    printf("%s: [Input] OpenInputDev001 enter %d\n", __func__, __LINE__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    int32_t ret = g_inputInterface->iInputManager->OpenInputDevice(VALUE_DEFAULT);
    if (ret != INPUT_SUCCESS) {
        printf("%s: open device1 failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: OpenInputDevice002
  * @tc.desc: open input device test
  * @tc.type: FUNC
  * @tc.require: AR000F867R
  */
HWTEST_F(HdiInputTest, OpenInputDevice002, TestSize.Level0)
{
    printf("%s: [Input] OpenInputDev002 enter %d\n", __func__, __LINE__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    /* Device "15" is used for testing nonexistent device node */
    int32_t ret = g_inputInterface->iInputManager->OpenInputDevice(INVALID_INDEX);
    if (ret != HDF_SUCCESS) {
        printf("%s: device %d dose not exist, can't open it, ret %d\n", __func__, INVALID_INDEX, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}


/**
  * @tc.name: OpenInputDevice003
  * @tc.desc: open input device test
  * @tc.type: FUNC
  * @tc.require: AR000F867R
  */
HWTEST_F(HdiInputTest, OpenInputDevice003, TestSize.Level0)
{
    printf("%s: [Input] OpenInputDev003 enter %d\n", __func__, __LINE__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    /* Device "-1" is used for testing nonexistent device node */
    int32_t ret = g_inputInterface->iInputManager->OpenInputDevice(INVALID_INDEX1);
    if (ret != HDF_SUCCESS) {
        printf("%s: device %d dose not exist, can't open it, ret %d\n", __func__, INVALID_INDEX1, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: CloseInputDevice001
  * @tc.desc: close input device test
  * @tc.type: FUNC
  * @tc.require: AR000F867T, AR000F8QNL
  */
HWTEST_F(HdiInputTest, CloseInputDevice001, TestSize.Level0)
{
    printf("%s: [Input] CloseInputDev001 enter %d\n", __func__, __LINE__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    int32_t ret = g_inputInterface->iInputManager->CloseInputDevice(VALUE_DEFAULT);
    if (ret != INPUT_SUCCESS) {
        printf("%s: close device %d failed, ret %d\n", __func__, g_touchIndex, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: CloseInputDevice002
  * @tc.desc: close input device test
  * @tc.type: FUNC
  * @tc.require: AR000F867T
  */
HWTEST_F(HdiInputTest, CloseInputDevice002, TestSize.Level0)
{
    printf("%s: [Input] CloseInputDev002 enter %d\n", __func__, __LINE__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    /* Device "15" is used for testing nonexistent device node */
    int32_t ret = g_inputInterface->iInputManager->CloseInputDevice(INVALID_INDEX);
    if (ret == INPUT_FAILURE) {
        printf("%s: device %d doesn't exist, can't close it, ret %d\n", __func__, INVALID_INDEX, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: CloseInputDevice003
  * @tc.desc: close input device test
  * @tc.type: FUNC
  * @tc.require: AR000F867T
  */
HWTEST_F(HdiInputTest, CloseInputDevice003, TestSize.Level0)
{
    printf("%s: [Input] CloseInputDev002 enter %d\n", __func__, __LINE__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    /* Device "-1" is used for testing nonexistent device node */
    int32_t ret = g_inputInterface->iInputManager->CloseInputDevice(INVALID_INDEX1);
    if (ret == INPUT_FAILURE) {
        printf("%s: device %d doesn't exist, can't close it, ret %d\n", __func__, INVALID_INDEX1, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetInputDevice001
  * @tc.desc: get input device info test
  * @tc.type: FUNC
  * @tc.require: AR000F867S
  */
HWTEST_F(HdiInputTest, GetInputDevice001, TestSize.Level0)
{
    printf("%s: [Input] GetInputDevice001 enter %d\n", __func__, __LINE__);
    InputDeviceInfo *dev = nullptr;
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    int32_t ret = g_inputInterface->iInputManager->GetInputDevice(g_touchIndex, &dev);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device %d failed, ret %d\n", __func__, g_touchIndex, ret);
    }
    printf("GetInputDevice001 %s: devIndex = %u, devType = %u\n", __func__, dev->devIndex, dev->devType);
    printf("GetInputDevice001: chipInfo = %s, vendorName = %s, chipName = %s, devName = %s\n",
        dev->chipInfo, dev->vendorName, dev->chipName, dev->attrSet.devName);
    printf("GetInputDevice001: busType = %u, vendor = %u, product = %u, version = %u\n",
        dev->attrSet.id.busType, dev->attrSet.id.vendor, dev->attrSet.id.product, dev->attrSet.id.version);
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetInputDevice002
  * @tc.desc: get input device info test
  * @tc.type: FUNC
  * @tc.require: AR000F867S
  */
HWTEST_F(HdiInputTest, GetInputDevice002, TestSize.Level0)
{
    printf("%s: [Input] GetInputDevice002 enter %d\n", __func__, __LINE__);
    InputDeviceInfo *dev = nullptr;
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    int32_t ret = g_inputInterface->iInputManager->GetInputDevice(INVALID_INDEX1, &dev);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device %d failed, ret %d\n", __func__, INVALID_INDEX1, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetInputDevice003
  * @tc.desc: get input device info test
  * @tc.type: FUNC
  * @tc.require: AR000F867S
  */
HWTEST_F(HdiInputTest, GetInputDevice003, TestSize.Level0)
{
    printf("%s: [Input] GetInputDevice003 enter %d\n", __func__, __LINE__);
    InputDeviceInfo *dev = nullptr;
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    int32_t ret = g_inputInterface->iInputManager->GetInputDevice(INVALID_INDEX, &dev);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device %d failed, ret %d\n", __func__, INVALID_INDEX, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetInputDeviceList001
  * @tc.desc: get input device list info test
  * @tc.type: FUNC
  * @tc.require: AR000F8680
  */
HWTEST_F(HdiInputTest, GetInputDeviceList001, TestSize.Level0)
{
    printf("%s: [Input] GetInputDeviceList001 enter\n", __func__);
    int32_t ret;
    uint32_t num = 0;
    InputDeviceInfo *dev = nullptr;
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    ret = g_inputInterface->iInputManager->GetInputDeviceList(&num, &dev, MAX_INPUT_DEV_NUM);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device list failed, ret %d\n", __func__, ret);
    }
    /* num <= MAX_INPUT_DEV_NUM return true */
    ASSERT_LE(num, MAX_INPUT_DEV_NUM);
    for (uint32_t i = 0; i < num; i++) {
        printf("%s: num = %u, device[%u]'s info is:\n", __func__, num, i);
        printf("%s: index = %u, devType = %u\n", __func__, (dev + i)->devIndex, (dev + i)->devType);
        printf("%s: chipInfo = %s, vendorName = %s, chipName = %s, devName = %s\n",
            __func__, (dev + i)->chipInfo, (dev + i)->vendorName, (dev + i)->chipName, (dev + i)->attrSet.devName);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RegisterCallbackAndReportData001
  * @tc.desc: get input device chip info test
  * @tc.type: FUNC
  * @tc.require: AR000F8682, AR000F8QNL
  */
HWTEST_F(HdiInputTest, RegisterCallbackAndReportData001, TestSize.Level0)
{
    printf("%s: [Input] RegisterCallbackAndReportData001 enter\n", __func__);
    int32_t ret;
    g_callback.EventPkgCallback = ReportEventPkgCallback;
    g_hotplugCb.HotPlugCallback = ReportHotPlugEventPkgCallback;
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputReporter, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    ret  = g_inputInterface->iInputReporter->RegisterReportCallback(g_touchIndex, &g_callback);
    if (ret != INPUT_SUCCESS) {
        printf("%s: register callback failed for device %d, ret %d\n", __func__, g_touchIndex, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterface->iInputManager->OpenInputDevice(VALUE_DEFAULT);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    printf("%s: wait 3s for testing, pls touch the panel now\n", __func__);
    printf("%s: The event data is as following:\n", __func__);
    OsalMSleep(KEEP_ALIVE_TIME_MS);
}

/**
  * @tc.name: RegisterReportCallback001
  * @tc.desc: register report callback fail
  * @tc.type: FUNC
  * @tc.require: AR000F8682, AR000F8QNL
  */
HWTEST_F(HdiInputTest, RegisterReportCallback001, TestSize.Level0)
{
    printf("%s: [Input] RegisterReportCallback001 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputReporter, INPUT_NULL_PTR);
    int32_t ret;
    ret = g_inputInterface->iInputReporter->RegisterReportCallback(0, nullptr);
    if (ret != INPUT_SUCCESS) {
        printf("%s: register report callback failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: UnregisterReportCallback001
  * @tc.desc: get input device chip info test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, UnregisterReportCallback001, TestSize.Level0)
{
    printf("%s: [Input] UnregisterReportCallback001 enter\n", __func__);
    int32_t ret;
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputReporter, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);

    ret  = g_inputInterface->iInputReporter->UnregisterReportCallback(g_touchIndex);
    if (ret != INPUT_SUCCESS) {
        printf("%s: unregister callback failed for device %d, ret %d\n", __func__, g_touchIndex, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
    ret = g_inputInterface->iInputManager->CloseInputDevice(VALUE_DEFAULT);
    if (ret != INPUT_SUCCESS) {
        printf("%s: close device %d failed, ret %d\n", __func__, g_touchIndex, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: UnRegisterReportCallback001
  * @tc.desc: unregister report callback fail
  * @tc.type: FUNC
  * @tc.require: AR000F8682, AR000F8QNL
  */
HWTEST_F(HdiInputTest, UnRegisterReportCallback001, TestSize.Level0)
{
    printf("%s: [Input] UnRegisterReportCallback001 enter\n", __func__);
    int32_t ret;
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputReporter, INPUT_NULL_PTR);
    ret = g_inputInterface->iInputReporter->UnregisterReportCallback(INVALID_DEV_INDEX);
    if (ret != INPUT_SUCCESS) {
        printf("%s: unregister report callback failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}


/**
  * @tc.name: FindIndexFromFd
  * @tc.desc: find index from fd test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, FindIndexFromFd001, TestSize.Level0)
{
    printf("%s: [Input] FindIndexFromFd001 enter\n", __func__);
    int32_t ret;
    InputDeviceManager InputDeviceManagerTest;
    int32_t fd = VALUE_NULL;
    uint32_t index = VALUE_NULL;
    ret = InputDeviceManagerTest.FindIndexFromFd(fd, &index);
    if (ret != INPUT_SUCCESS) {
        printf("%s: find index from fd failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: FindIndexFromDevName
  * @tc.desc: find index from device name test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, FindIndexFromDevName001, TestSize.Level0)
{
    printf("%s: [Input] FindIndexFromDevName001 enter\n", __func__);
    int32_t ret;
    InputDeviceManager InputDeviceManagerTest;
    string devName = "MOUSE1";
    uint32_t index = VALUE_NULL;
    ret = InputDeviceManagerTest.FindIndexFromDevName(devName, &index);
    if (ret != INPUT_SUCCESS) {
        printf("%s: find index from device name failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetPowerStatus
  * @tc.desc: set power status test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, SetPowerStatus001, TestSize.Level0)
{
    printf("%s: [Input] SetPowerStatus001 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t status = VALUE_NULL;
    ret = g_inputInterface->iInputController->SetPowerStatus(g_touchIndex, status);
    if (ret != INPUT_SUCCESS) {
        printf("%s: set power status failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetPowerStatus
  * @tc.desc: set power status test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, SetPowerStatus002, TestSize.Level0)
{
    printf("%s: [Input] SetPowerStatus002 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t status = VALUE_NULL;
    ret = g_inputInterface->iInputController->SetPowerStatus(INVALID_INDEX, status);
    if (ret != INPUT_SUCCESS) {
        printf("%s: set power status failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetPowerStatus
  * @tc.desc: set power status test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, SetPowerStatus003, TestSize.Level0)
{
    printf("%s: [Input] SetPowerStatus003 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t status = VALUE_NULL;
    ret = g_inputInterface->iInputController->SetPowerStatus(INVALID_INDEX1, status);
    if (ret != INPUT_SUCCESS) {
        printf("%s: set power status failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetPowerStatus
  * @tc.desc: get power status test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetPowerStatus001, TestSize.Level0)
{
    printf("%s: [Input] GetPowerStatus001 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t status = VALUE_NULL;
    ret = g_inputInterface->iInputController->GetPowerStatus(g_touchIndex, &status);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get power status failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetPowerStatus
  * @tc.desc: get power status test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetPowerStatus002, TestSize.Level0)
{
    printf("%s: [Input] GetPowerStatus002 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t status = VALUE_NULL;
    ret = g_inputInterface->iInputController->GetPowerStatus(INVALID_INDEX, &status);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get power status failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetPowerStatus
  * @tc.desc: get power status test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetPowerStatus003, TestSize.Level0)
{
    printf("%s: [Input] GetPowerStatus003 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t status = VALUE_NULL;
    ret = g_inputInterface->iInputController->GetPowerStatus(INVALID_INDEX1, &status);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get power status failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetDeviceType
  * @tc.desc: get device type test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetDeviceType001, TestSize.Level0)
{
    printf("%s: [Input] GetDeviceType001 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t deviceType = INIT_DEFAULT_VALUE;
    ret = g_inputInterface->iInputController->GetDeviceType(g_touchIndex, &deviceType);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device type failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetDeviceType
  * @tc.desc: get device type test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetDeviceType002, TestSize.Level0)
{
    printf("%s: [Input] GetDeviceType002 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t deviceType = INIT_DEFAULT_VALUE;
    ret = g_inputInterface->iInputController->GetDeviceType(INVALID_INDEX, &deviceType);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device type failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetDeviceType
  * @tc.desc: get device type test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetDeviceType003, TestSize.Level0)
{
    printf("%s: [Input] GetDeviceType003 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t deviceType = INIT_DEFAULT_VALUE;
    ret = g_inputInterface->iInputController->GetDeviceType(INVALID_INDEX1, &deviceType);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device type failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipInfo
  * @tc.desc: get input device chip info test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetChipInfo001, TestSize.Level0)
{
    printf("%s: [Input] GetChipInfo001 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char chipInfo[TEST_LEN1] = {0};
    ret = g_inputInterface->iInputController->GetChipInfo(g_touchIndex, chipInfo, TEST_LEN1);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get chip info failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipInfo
  * @tc.desc: get input device chip info test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetChipInfo002, TestSize.Level0)
{
    printf("%s: [Input] GetChipInfo002 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char chipInfo[TEST_LEN1] = {0};
    ret = g_inputInterface->iInputController->GetChipInfo(INVALID_INDEX, chipInfo, TEST_LEN1);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get chip info failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipInfo
  * @tc.desc: get input device chip info test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetChipInfo003, TestSize.Level0)
{
    printf("%s: [Input] GetChipInfo003 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char chipInfo[TEST_LEN1] = {0};
    ret = g_inputInterface->iInputController->GetChipInfo(g_touchIndex, chipInfo, TEST_LEN2);
    if (ret != INPUT_SUCCESS) {
        printf("%s: get device chip info failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetVendorName
  * @tc.desc: get device vendor name test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetVendorName001, TestSize.Level0)
{
    printf("%s: [Input] GetVendorName001 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char vendorName[TEST_LEN1] = {0};
    ret = g_inputInterface->iInputController->GetVendorName(g_touchIndex, vendorName, TEST_LEN1);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device vendor name failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetVendorName
  * @tc.desc: get device vendor name test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetVendorName002, TestSize.Level0)
{
    printf("%s: [Input] GetVendorName002 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char vendorName[TEST_LEN1] = {0};
    ret = g_inputInterface->iInputController->GetVendorName(INVALID_INDEX, vendorName, TEST_LEN1);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device vendor name failed, ret %d", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetVendorName
  * @tc.desc: get device vendor name test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetVendorName003, TestSize.Level0)
{
    printf("%s: [Input] GetVendorName003 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char vendorName[TEST_LEN1] = {0};
    ret = g_inputInterface->iInputController->GetVendorName(g_touchIndex, vendorName, TEST_LEN2);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device vendor name failed, ret %d", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipName
  * @tc.desc: get device chip name test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetChipName001, TestSize.Level0)
{
    printf("%s: [Input] GetChipName001 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char chipName[TEST_LEN1] = {0};
    ret = g_inputInterface->iInputController->GetChipName(g_touchIndex, chipName, TEST_LEN1);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device chip name failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipName
  * @tc.desc: get device chip name test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetChipName002, TestSize.Level0)
{
    printf("%s: [Input] GetChipName002 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char chipName[TEST_LEN1] = {0};
    ret = g_inputInterface->iInputController->GetChipName(INVALID_INDEX, chipName, TEST_LEN1);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device chip name failed, ret %d", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetChipName
  * @tc.desc: get device chip name test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetChipName003, TestSize.Level0)
{
    printf("%s: [Input] GetChipName003 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char chipName[TEST_LEN1] = {0};
    ret = g_inputInterface->iInputController->GetChipName(g_touchIndex, chipName, TEST_LEN2);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: get device chip name failed, ret %d", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetGestureMode
  * @tc.desc: set device gestureMode test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, SetGestureMode001, TestSize.Level0)
{
    printf("%s: [Input] SetGestureMode001 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t gestureMode = VALUE_DEFAULT;
    ret = g_inputInterface->iInputController->SetGestureMode(g_touchIndex, gestureMode);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: set device gestureMode failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SetGestureMode
  * @tc.desc: set device gestureMode test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, SetGestureMode002, TestSize.Level0)
{
    printf("%s: [Input] SetGestureMode002 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    uint32_t gestureMode = VALUE_DEFAULT;
    ret = g_inputInterface->iInputController->SetGestureMode(INVALID_INDEX, gestureMode);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: set device gestureMode failed, ret %d", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RunCapacitanceTest
  * @tc.desc: run capacitance test test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, RunCapacitanceTest001, TestSize.Level0)
{
    printf("%s: [Input] RunCapacitanceTest001 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char result[TEST_RESULT_LEN] = {0};
    uint32_t testType = TEST_TYPE;
    ret = g_inputInterface->iInputController->RunCapacitanceTest(g_touchIndex, testType, result, TEST_RESULT_LEN);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: run capacitance test failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RunCapacitanceTest002
  * @tc.desc: run capacitance test test002
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, RunCapacitanceTest002, TestSize.Level0)
{
    printf("%s: [Input] RunCapacitanceTest002 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    char result[TEST_RESULT_LEN] = {0};
    uint32_t testType = TEST_TYPE;
    ret = g_inputInterface->iInputController->RunCapacitanceTest(g_touchIndex, testType, nullptr, TEST_RESULT_LEN);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: run capacitance test002 failed, ret %d", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RunExtraCommand
  * @tc.desc: run extra command test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, RunExtraCommand001, TestSize.Level0)
{
    printf("%s: [Input] RunExtraCommand001 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    InputExtraCmd extraCmd = {0};
    extraCmd.cmdCode = "WakeUpMode";
    extraCmd.cmdValue = "Enable";
    ret = g_inputInterface->iInputController->RunExtraCommand(g_touchIndex, &extraCmd);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: run extra command failed, ret %d", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RunExtraCommand
  * @tc.desc: run extra command test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, RunExtraCommand002, TestSize.Level0)
{
    printf("%s: [Input] RunExtraCommand002 enter\n", __func__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputController, INPUT_NULL_PTR);

    int32_t ret;
    InputExtraCmd extraCmd = {0};
    extraCmd.cmdCode = "WakeUpMode";
    extraCmd.cmdValue = "Enable";
    ret = g_inputInterface->iInputController->RunExtraCommand(INVALID_INDEX, &extraCmd);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%s: run extra command failed, ret %d", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: RegisterHotPlugCallback
  * @tc.desc: Register Hot Plug Callback
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, RegisterHotPlugCallback001, TestSize.Level0)
{
    printf("%s: [Input] RegisterHotPlugCallback001 enter\n", __func__);
    int32_t ret;
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputReporter, INPUT_NULL_PTR);

    ret  = g_inputInterface->iInputReporter->RegisterHotPlugCallback(&g_hotplugCb);
    if (ret != INPUT_SUCCESS) {
        printf("%s: Register Hot Plug Callback failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: UnregisterHotPlugCallback
  * @tc.desc: Unregister Hot Plug Callback
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, UnregisterHotPlugCallback001, TestSize.Level0)
{
    printf("%s: [Input] UnregisterHotPlugCallback001 enter\n", __func__);
    int32_t ret;
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputReporter, INPUT_NULL_PTR);

    ret  = g_inputInterface->iInputReporter->UnregisterHotPlugCallback();
    if (ret != INPUT_SUCCESS) {
        printf("%s: Unregister Hot Plug Callback failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: SendHotPlugEvent
  * @tc.desc: Send Hot Plug Event
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, SendHotPlugEvent001, TestSize.Level1)
{
    printf("%s: [Input] SendHotPlugEvent001 enter\n", __func__);
    LOG_SetCallback(MyLogCallback);
    InputDeviceManager iInputDeviceManager;
    iInputDeviceManager.SendHotPlugEvent(g_type, g_index, STATUS);
    EXPECT_TRUE(g_errLog.find("SendHotPlugEvent") != std::string::npos);
}

/**
  * @tc.name: DoWithEventDeviceAdd
  * @tc.desc: Do With Event Device Add
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, DoWithEventDeviceAdd001, TestSize.Level1)
{
    printf("%s: [Input] DoWithEventDeviceAdd001 enter\n", __func__);
    LOG_SetCallback(MyLogCallback);
    InputDeviceManager iInputDeviceManager;
    iInputDeviceManager.DoWithEventDeviceAdd(g_fileDescriptorFirst, g_fileDescriptorSecond, NODE_PATH);
    EXPECT_TRUE(g_errLog.find("DoWithEventDeviceAdd") != std::string::npos);
}

/**
  * @tc.name: DoWithEventDeviceDel
  * @tc.desc: Do With Event Device Del
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, DoWithEventDeviceDel001, TestSize.Level1)
{
    printf("%s: [Input] DoWithEventDeviceDel001 enter\n", __func__);
    LOG_SetCallback(MyLogCallback);
    InputDeviceManager iInputDeviceManager;
    iInputDeviceManager.DoWithEventDeviceDel(g_fileDescriptorFirst, g_index);
    EXPECT_TRUE(g_errLog.find("DoWithEventDeviceDel") != std::string::npos);
}

/**
  * @tc.name: ReportEventPkg001
  * @tc.desc: Report Event Pkg
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, ReportEventPkg001, TestSize.Level1)
{
    printf("%s: [Input] ReportEventPkg001 enter\n", __func__);
    LOG_SetCallback(MyLogCallback);
    InputEventPackage **evtPkg = (InputEventPackage **)OsalMemAlloc(sizeof(InputEventPackage *) * COUNT);
    INPUT_CHECK_NULL_POINTER(evtPkg, INPUT_NULL_PTR);
    InputDeviceManager iInputDeviceManager;
    iInputDeviceManager.ReportEventPkg(g_fileDescriptorFirst, evtPkg, COUNT);
    EXPECT_TRUE(g_errLog.find("ReportEventPkg") != std::string::npos);
}

/**
  * @tc.name: DoRead
  * @tc.desc: Do Read
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, DoRead001, TestSize.Level1)
{
    printf("%s: [Input] DoRead001 enter\n", __func__);
    LOG_SetCallback(MyLogCallback);
    struct input_event evtBuffer[EVENT_BUFFER_SIZE] {};
    InputDeviceManager iInputDeviceManager;
    iInputDeviceManager.DoRead(g_fileDescriptorFirst, evtBuffer, EVENT_BUFFER_SIZE);
    EXPECT_TRUE((g_errLog.find("DoRead") != std::string::npos) ||
        (g_errLog.find("CheckReadResult") != std::string::npos));
}

/**
  * @tc.name: InotifyEventHandler
  * @tc.desc: Inotify Event Handler
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, InotifyEventHandler001, TestSize.Level1)
{
    printf("%s: [Input] InotifyEventHandler001 enter\n", __func__);
    int32_t ret;
    struct input_event evtBuffer[EVENT_BUFFER_SIZE] {};
    InputDeviceManager iInputDeviceManager;
    ret = iInputDeviceManager.InotifyEventHandler(g_fileDescriptorFirst, g_fileDescriptorSecond);
    if (ret != INPUT_SUCCESS) {
        printf("%s: Inotify Event Handler failed, ret %d\n", __func__, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: ScanDevice
  * @tc.desc: Scan Device Fail
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, ScanDevice001, TestSize.Level0)
{
    printf("%s: [Input] ScanDevice001 enter\n", __func__);
    int32_t ret;
    InputDeviceManager iInputDeviceManager;
    ret = iInputDeviceManager.ScanDevice(nullptr, 0);
    if (ret != INPUT_SUCCESS) {
        printf("%s: Scan Device failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}

/**
  * @tc.name: GetDeviceList
  * @tc.desc: Get Device List Fail
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, GetDeviceList001, TestSize.Level0)
{
    printf("%s: [Input] GetDeviceList001 enter\n", __func__);
    int32_t ret;
    InputDeviceManager iInputDeviceManager;
    ret = iInputDeviceManager.GetDeviceList(nullptr, nullptr, 0);
    if (ret != INPUT_SUCCESS) {
        printf("%s: Get Device List Failed, ret %d\n", __func__, ret);
    }
    EXPECT_NE(ret, INPUT_SUCCESS);
}
