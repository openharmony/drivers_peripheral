/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "usbd_function_test.h"

#include <iostream>

#include "hdf_log.h"
#include "if_system_ability_manager.h"
#include "system_ability_definition.h"
#include "usbd_function.h"
#include "usbd_port.h"
#include "usbd_wrapper.h"
#include "v2_0/iusb_device_interface.h"
#include "v2_0/iusb_port_interface.h"
#include "v2_0/usb_types.h"

constexpr int32_t SLEEP_TIME = 3;
constexpr int32_t USB_FUNCTION_INVALID = -1;
constexpr int32_t USB_PORT_ID_INVALID = 2;
constexpr int32_t USB_POWER_ROLE_INVALID = 4;
constexpr int32_t USB_DATA_ROLE_INVALID = 5;
constexpr int32_t USB_FUNCTION_UNSUPPORTED = 128;

using namespace testing::ext;
using namespace OHOS;
using namespace std;
using namespace OHOS::HDI::Usb::V2_0;

namespace {
sptr<IUsbPortInterface> g_usbPortInterface = nullptr;
sptr<IUsbDeviceInterface> g_usbDeviceInterface = nullptr;

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbdFunctionTest::SetUpTestCase(void)
{
    g_usbDeviceInterface = IUsbDeviceInterface::Get();
    g_usbPortInterface = IUsbPortInterface::Get();
    if (g_usbDeviceInterface == nullptr || g_usbPortInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    auto ret = g_usbPortInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SINK, DATA_ROLE_DEVICE);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdFunctionTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    ASSERT_EQ(0, ret);
    if (ret != 0) {
        exit(0);
    }
}

void UsbdFunctionTest::TearDownTestCase(void) {}

void UsbdFunctionTest::SetUp(void) {}

void UsbdFunctionTest::TearDown(void) {}

/**
 * @tc.name: UsbdGetCurrentFunctions001
 * @tc.desc: Test functions to GetCurrentFunctions
 * @tc.desc: int32_t GetCurrentFunctions(int32_t &funcs);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdGetCurrentFunctions001, TestSize.Level1)
{
    int32_t func = USB_FUNCTION_NONE;
    auto ret = g_usbDeviceInterface->GetCurrentFunctions(func);
    HDF_LOGI("UsbdFunctionTest::UsbdGetCurrentFunctions001 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdGetCurrentFunctions002
 * @tc.desc: Test functions to GetCurrentFunctions
 * @tc.desc: int32_t GetCurrentFunctions(int32_t &funcs);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdGetCurrentFunctions002, TestSize.Level1)
{
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_ACM);
    HDF_LOGI("UsbdFunctionTest::UsbdFunction011 %{public}d SetCurrentFunctions=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    int32_t func = USB_FUNCTION_NONE;
    ret = g_usbDeviceInterface->GetCurrentFunctions(func);
    HDF_LOGI("UsbdFunctionTest::UsbdFunction001 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdSetCurrentFunctions001
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions001, TestSize.Level1)
{
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_ACM);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions001 %{public}d SetCurrentFunctions=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions002
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Negative test: parameters exception, funcs error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions002, TestSize.Level1)
{
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_INVALID);
    HDF_LOGI("UsbdFunctionTest::UsbdFunction002 %{public}d, ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}
/**
 * @tc.name: UsbdSetCurrentFunctions003
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions003, TestSize.Level1)
{
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_ECM);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions003 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions004
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions004, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_ACM | USB_FUNCTION_ECM;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions004 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions005
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions005, TestSize.Level1)
{
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_HDC);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions005 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions006
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions006, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_ACM | USB_FUNCTION_HDC;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions006 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions007
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions007, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_ECM | USB_FUNCTION_HDC;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions007 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions008
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions008, TestSize.Level1)
{
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_RNDIS);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions008 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions009
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions009, TestSize.Level1)
{
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_STORAGE);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions009 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions010
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions010, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_RNDIS | USB_FUNCTION_HDC;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions010 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions011
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions011, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_STORAGE | USB_FUNCTION_HDC;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions011 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions012
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions012, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_MTP;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions012 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions013
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions013, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_PTP;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions013 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions014
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions014, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_MTP | USB_FUNCTION_HDC;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions014 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions015
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions015, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_PTP | USB_FUNCTION_HDC;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions015 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions016
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions016, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_MTP | USB_FUNCTION_RNDIS;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions016 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions017
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions017, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_PTP | USB_FUNCTION_RNDIS;
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions017 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions018
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Negative test: parameters exception, funcs error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions018, TestSize.Level1)
{
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_UNSUPPORTED);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions018 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetCurrentFunctions019
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions019, TestSize.Level1)
{
    auto ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_NONE);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions013 ret=%{public}d", ret);
    ASSERT_EQ(0, ret);
    HDF_LOGI("UsbdFunctionTest::the function was set to none successfully");
    ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_HDC);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetPortRole001
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole001, TestSize.Level1)
{
    auto ret = g_usbPortInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SOURCE, DATA_ROLE_HOST);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole001 %{public}d ret=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetPortRole002
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Negative test: parameters exception, portId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole002, TestSize.Level1)
{
    auto ret = g_usbPortInterface->SetPortRole(USB_PORT_ID_INVALID, POWER_ROLE_SOURCE, DATA_ROLE_HOST);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole002 %{public}d ret=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetPortRole003
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Negative test: parameters exception, powerRole error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole003, TestSize.Level1)
{
    auto ret = g_usbPortInterface->SetPortRole(DEFAULT_PORT_ID, USB_POWER_ROLE_INVALID, DATA_ROLE_DEVICE);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole003 %{public}d ret=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetPortRole004
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Negative test: parameters exception, dataRole error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole004, TestSize.Level1)
{
    auto ret = g_usbPortInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SOURCE, USB_DATA_ROLE_INVALID);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole004 %{public}d ret=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetPortRole005
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Negative test: parameters exception, powerRole error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole005, TestSize.Level1)
{
    auto ret = g_usbPortInterface->SetPortRole(DEFAULT_PORT_ID, USB_POWER_ROLE_INVALID, DATA_ROLE_HOST);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole005 %{public}d ret=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetPortRole006
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Negative test: parameters exception, portId && dataRole error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole006, TestSize.Level1)
{
    auto ret = g_usbPortInterface->SetPortRole(USB_PORT_ID_INVALID, POWER_ROLE_SOURCE, USB_DATA_ROLE_INVALID);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole006 %{public}d ret=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetPortRole007
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Negative test: parameters exception, powerRole && dataRole error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole007, TestSize.Level1)
{
    auto ret = g_usbPortInterface->SetPortRole(DEFAULT_PORT_ID, USB_POWER_ROLE_INVALID, USB_DATA_ROLE_INVALID);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole007 %{public}d ret=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetPortRole008
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Negative test: parameters exception, portId && powerRole && dataRole error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole008, TestSize.Level1)
{
    auto ret = g_usbPortInterface->SetPortRole(USB_PORT_ID_INVALID, USB_POWER_ROLE_INVALID, USB_DATA_ROLE_INVALID);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole008 %{public}d ret=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: SetPortRole009
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, SetPortRole09, TestSize.Level1)
{
    auto ret = g_usbPortInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SINK, DATA_ROLE_DEVICE);
    HDF_LOGI("UsbdFunctionTest::SetPortRole09 %{public}d ret=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: QueryPort001
 * @tc.desc: Test functions to QueryPort
 * @tc.desc: int32_t QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, QueryPort001, TestSize.Level1)
{
    int32_t portId = DEFAULT_PORT_ID;
    int32_t powerRole = POWER_ROLE_NONE;
    int32_t dataRole = DATA_ROLE_NONE;
    int32_t mode = PORT_MODE_NONE;
    auto ret = g_usbPortInterface->QueryPort(portId, powerRole, dataRole, mode);
    HDF_LOGI("UsbdFunctionTest::QueryPort001 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}
} // namespace
