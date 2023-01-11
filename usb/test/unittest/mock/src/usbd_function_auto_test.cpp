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

#include <iostream>
#include <gtest/gtest.h>
#include "hdf_log.h"
#include "if_system_ability_manager.h"
#include "system_ability_definition.h"
#include "usbd_function.h"
#include "usbd_port.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"

constexpr int32_t PORT_ID_INVALID = 2;
constexpr int32_t POWER_ROLE_INVALID = 4;
constexpr int32_t DATA_ROLE_INVALID = 5;
constexpr int32_t USB_FUNCTION_UNSUPPORTED = 128;

using namespace testing::ext;
using namespace OHOS;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;

namespace {
sptr<IUsbInterface> g_usbInterface = nullptr;

class UsbdFunctionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void UsbdFunctionTest::SetUpTestCase(void)
{
    g_usbInterface = IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
}

void UsbdFunctionTest::TearDownTestCase(void) {}

/**
 * @tc.name: UsbdSetCurrentFunctions001
 * @tc.desc: Test functions to SetCurrentFunctions
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Negative test: parameters exception, funcs error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetCurrentFunctions001, TestSize.Level1)
{
    auto ret = g_usbInterface->SetCurrentFunctions(USB_FUNCTION_UNSUPPORTED);
    HDF_LOGI("UsbdFunctionTest::UsbdSetCurrentFunctions001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetPortRole001
 * @tc.desc: Test functions to SetPortRole
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Negative test: parameters exception, portId && powerRole && dataRole error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdFunctionTest, UsbdSetPortRole001, TestSize.Level1)
{
    auto ret = g_usbInterface->SetPortRole(PORT_ID_INVALID, POWER_ROLE_INVALID, DATA_ROLE_INVALID);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole001 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
    auto ret = g_usbInterface->SetPortRole(PORT_ID_INVALID, POWER_ROLE_SOURCE, DATA_ROLE_HOST);
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
    auto ret = g_usbInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_INVALID, DATA_ROLE_DEVICE);
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
    auto ret = g_usbInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SOURCE, DATA_ROLE_INVALID);
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
    auto ret = g_usbInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_INVALID, DATA_ROLE_INVALID);
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
    auto ret = g_usbInterface->SetPortRole(PORT_ID_INVALID, POWER_ROLE_SOURCE, DATA_ROLE_INVALID);
    HDF_LOGI("UsbdFunctionTest::UsbdSetPortRole006 %{public}d ret=%{public}d", __LINE__, ret);
    ASSERT_NE(ret, 0);
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
