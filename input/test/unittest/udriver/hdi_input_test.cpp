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
#include "hdf_log.h"
#include "input_device_manager.h"
#include "input_manager.h"
#include "osal_time.h"

using namespace testing::ext;
using namespace OHOS::Input;
static IInputInterface *g_inputInterface;
static InputEventCb g_callback;
static InputHostCb g_hotplugCb;
static int32_t g_touchIndex;
static const int32_t KEEP_ALIVE_TIME_MS = 3000;
static const int32_t INVALID_INDEX = 15;
static const int32_t INVALID_INDEX1 = -1;
static const int32_t MAX_DEVICES = 32;
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
    if (g_inputInterface != nullptr) {
        free(g_inputInterface);
        g_inputInterface = nullptr;
    }
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
HWTEST_F(HdiInputTest, ScanInputDevice001, TestSize.Level1)
{
    InputDevDesc sta[MAX_DEVICES] = {0};
    printf("%s: [Input] ScanInputDevice001 enter %d\n", __func__, __LINE__);
    int32_t ret;
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
  * @tc.name: OpenInputDev001
  * @tc.desc: open input device test
  * @tc.type: FUNC
  * @tc.require: AR000F867R
  */
HWTEST_F(HdiInputTest, OpenInputDev001, TestSize.Level1)
{
    printf("%s: [Input] OpenInputDev001 enter %d\n", __func__, __LINE__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    int32_t ret = g_inputInterface->iInputManager->OpenInputDevice(g_touchIndex);
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
HWTEST_F(HdiInputTest, OpenInputDevice002, TestSize.Level1)
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
HWTEST_F(HdiInputTest, OpenInputDevice003, TestSize.Level1)
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
HWTEST_F(HdiInputTest, CloseInputDevice001, TestSize.Level1)
{
    printf("%s: [Input] CloseInputDev001 enter %d\n", __func__, __LINE__);
    INPUT_CHECK_NULL_POINTER(g_inputInterface, INPUT_NULL_PTR);
    INPUT_CHECK_NULL_POINTER(g_inputInterface->iInputManager, INPUT_NULL_PTR);
    int32_t ret = g_inputInterface->iInputManager->CloseInputDevice(g_touchIndex);
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
HWTEST_F(HdiInputTest, CloseInputDevice002, TestSize.Level1)
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
HWTEST_F(HdiInputTest, CloseInputDevice003, TestSize.Level1)
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
HWTEST_F(HdiInputTest, GetInputDevice001, TestSize.Level1)
{
    printf("%s: [Input] GetInputDevice001 enter %d\n", __func__, __LINE__);
    InputDeviceInfo *dev = new InputDeviceInfo();
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
HWTEST_F(HdiInputTest, GetInputDevice002, TestSize.Level1)
{
    printf("%s: [Input] GetInputDevice002 enter %d\n", __func__, __LINE__);
    InputDeviceInfo *dev = new InputDeviceInfo();
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
HWTEST_F(HdiInputTest, GetInputDevice003, TestSize.Level1)
{
    printf("%s: [Input] GetInputDevice003 enter %d\n", __func__, __LINE__);
    InputDeviceInfo *dev = new InputDeviceInfo();
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
HWTEST_F(HdiInputTest, GetInputDeviceList001, TestSize.Level1)
{
    printf("%s: [Input] GetInputDeviceList001 enter\n", __func__);
    int32_t ret;
    uint32_t num = 0;
    InputDeviceInfo *dev = new InputDeviceInfo[MAX_INPUT_DEV_NUM] {};
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
HWTEST_F(HdiInputTest, RegisterCallbackAndReportData001, TestSize.Level1)
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
    ret = g_inputInterface->iInputManager->OpenInputDevice(g_touchIndex);
    EXPECT_EQ(ret, INPUT_SUCCESS);
    printf("%s: wait 3s for testing, pls touch the panel now\n", __func__);
    printf("%s: The event data is as following:\n", __func__);
    OsalMSleep(KEEP_ALIVE_TIME_MS);
}

/**
  * @tc.name: UnregisterReportCallback001
  * @tc.desc: get input device chip info test
  * @tc.type: FUNC
  * @tc.require: SR000F867Q
  */
HWTEST_F(HdiInputTest, UnregisterReportCallback001, TestSize.Level1)
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
    ret = g_inputInterface->iInputManager->CloseInputDevice(g_touchIndex);
    if (ret != INPUT_SUCCESS) {
        printf("%s: close device %d failed, ret %d\n", __func__, g_touchIndex, ret);
    }
    EXPECT_EQ(ret, INPUT_SUCCESS);
}
