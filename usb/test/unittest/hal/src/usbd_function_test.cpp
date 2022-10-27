/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"

const int SLEEP_TIME = 3;
const int TEST_PORT_ID = 1;
const int TEST_POWER_ROLE = 2;
const int TEST_DATAR_ROLE = 2;
const int USB_FUNCTION_INVALID = -1;
const int USB_FUNCTION_ACM = 1;
const int USB_FUNCTION_ECM = 2;
const int USB_FUNCTION_HDC = 4;
const int USB_FUNCTION_RNDIS = 32;
const int USB_FUNCTION_STORAGE = 512;
const int USB_FUNCTION_UNSUPPORTED = 128;

using namespace testing::ext;
using namespace OHOS;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;

namespace {
sptr<IUsbInterface> g_usbInterface = nullptr;

void UsbdFunctionTest::SetUpTestCase(void)
{
    g_usbInterface = IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->SetPortRole(TEST_PORT_ID, TEST_POWER_ROLE, TEST_DATAR_ROLE);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdFunctionTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
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
    int32_t funcs = 0;
    auto ret = g_usbInterface->GetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdGetCurrentFunctions001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    auto ret = g_usbInterface->SetCurrentFunctions(1);
    HDF_LOGI("UsbdFunctionTest::UsbdFunction011 %{public}d SetCurrentFunctions=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    int32_t funcs = 1;
    ret = g_usbInterface->GetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdFunction001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    int32_t funcs = USB_FUNCTION_ACM;
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions001 %{public}d SetCurrentFunctions=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    int32_t funcs = USB_FUNCTION_INVALID;
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdFunction002 %{public}d, ret=%{public}d, funcs=%{public}d", __LINE__, ret, funcs);
    ASSERT_NE(ret, 0);
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
    int32_t funcs = USB_FUNCTION_ECM;
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    int32_t funcs = USB_FUNCTION_HDC;
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    int32_t funcs = USB_FUNCTION_RNDIS;
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    int32_t funcs = USB_FUNCTION_STORAGE;
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions009 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions010 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions0011 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetCurrentFunctions012
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Negative test: parameters exception, funcs error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions012, TestSize.Level1)
{
    int32_t funcs = USB_FUNCTION_UNSUPPORTED;
    auto ret = g_usbInterface->SetCurrentFunctions(funcs);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(0, ret);
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
    auto ret = g_usbInterface->SetPortRole(1, 1, 1);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    auto ret = g_usbInterface->SetPortRole(2, 1, 1);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole002 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    auto ret = g_usbInterface->SetPortRole(1, 4, 2);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole003 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    auto ret = g_usbInterface->SetPortRole(1, 1, 5);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole004 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetPortRole005
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Negative test: parameters exception, portId && powerRole error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole005, TestSize.Level1)
{
    auto ret = g_usbInterface->SetPortRole(1, 5, 5);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole005 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    auto ret = g_usbInterface->SetPortRole(5, 1, 5);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    auto ret = g_usbInterface->SetPortRole(1, 5, 5);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole007 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    auto ret = g_usbInterface->SetPortRole(2, 5, 5);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole008 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    auto ret = g_usbInterface->SetPortRole(1, 2, 2);
    HDF_LOGI("UsbdFunctionTest::SetPortRole09 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
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
    int32_t portId = 0;
    int32_t powerRole = 0;
    int32_t dataRole = 0;
    int32_t mode = 0;
    auto ret = g_usbInterface->QueryPort(portId, powerRole, dataRole, mode);
    HDF_LOGI("UsbdFunctionTest::QueryPort001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}
} // namespace
