/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "usbd_accessory_test.h"

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <vector>
#include <string>

#include "UsbSubscriberTest.h"
#include "hdf_log.h"
#include "v1_2/iusb_interface.h"
#include "v1_2/usb_types.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;
using namespace OHOS::HDI::Usb::V1_2;

sptr<UsbSubscriberTest> UsbdAccessoryTest::subscriber_ = nullptr;

sptr<OHOS::HDI::Usb::V1_2::IUsbInterface> g_usbInterface = nullptr;

void UsbdAccessoryTest::SetUpTestCase(void)
{
    g_usbInterface = OHOS::HDI::Usb::V1_2::IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    std::cout << "please connect accessory, press enter to continue" << std::endl;
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != EOF);
}

void UsbdAccessoryTest::TearDownTestCase(void)
{
}

void UsbdAccessoryTest::SetUp(void)
{
}

void UsbdAccessoryTest::TearDown(void)
{
}

/**
 * @tc.name: GetAccessoryInfo001
 * @tc.desc: Test functions to GetAccessoryInfo
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAccessoryTest, GetAccessoryInfo001, TestSize.Level1)
{
    HDF_LOGI("Case Start : GetAccessoryInfo001 : GetAccessoryInfo");
    vector<string> accessoryInfo;
    auto ret = g_usbInterface->GetAccessoryInfo(accessoryInfo);
    EXPECT_TRUE(ret == 0);
    HDF_LOGI("UsbdAccessoryTest::GetAccessoryInfo001 %{public}d ret=%{public}d", __LINE__, ret);
    EXPECT_TRUE(!accessoryInfo.empty()) << "accessoryInfo NULL";
    HDF_LOGI("UsbdAccessoryTest::GetAccessoryInfo001 %{public}d size=%{public}zu", __LINE__,
               accessoryInfo.size());
}

/**
 * @tc.name: OpenAccessory001
 * @tc.desc: Test functions to OpenAccessory
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAccessoryTest, OpenAccessory001, TestSize.Level1)
{
    HDF_LOGI("Case Start : OpenAccessory001 : OpenAccessory");
    int32_t fd;
    auto ret = g_usbInterface->OpenAccessory(fd);
    EXPECT_TRUE(ret == 0);
    HDF_LOGI("UsbdAccessoryTest::OpenAccessory001 %{public}d ret=%{public}d", __LINE__, ret);
    g_usbInterface->CloseAccessory(fd);
}

/**
 * @tc.name: OpenAccessory002
 * @tc.desc: Test functions to OpenAccessory
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAccessoryTest, OpenAccessory002, TestSize.Level1)
{
    HDF_LOGI("Case Start : OpenAccessory001 : OpenAccessory");
    int32_t fd;
    auto ret = g_usbInterface->OpenAccessory(fd);
    EXPECT_TRUE(ret == 0);
    HDF_LOGI("UsbdAccessoryTest::OpenAccessory002 %{public}d ret=%{public}d", __LINE__, ret);
    ret = g_usbInterface->OpenAccessory(fd);
    EXPECT_TRUE(ret != 0);
    HDF_LOGI("UsbdAccessoryTest::OpenAccessory002 %{public}d ret=%{public}d", __LINE__, ret);
    g_usbInterface->CloseAccessory(fd);
}

/**
 * @tc.name: CloseAccessory001
 * @tc.desc: Test functions to CloseAccessory
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAccessoryTest, CloseAccessory001, TestSize.Level1)
{
    HDF_LOGI("Case Start : CloseAccessory001 : CloseAccessory");
    int32_t fd;
    auto ret = g_usbInterface->OpenAccessory(fd);
    EXPECT_TRUE(ret == 0);
    HDF_LOGI("UsbdAccessoryTest::CloseAccessory001 %{public}d ret=%{public}d", __LINE__, ret);
    ret = g_usbInterface->CloseAccessory(fd);
    EXPECT_TRUE(ret == 0);
    HDF_LOGI("UsbdAccessoryTest::CloseAccessory001 %{public}d ret=%{public}d", __LINE__, ret);
}
