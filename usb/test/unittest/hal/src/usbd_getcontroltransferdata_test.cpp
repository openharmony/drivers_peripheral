/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <vector>

#include "usbd_getcontroltransferdata_test.h"
#include "hdf_log.h"
#include "usbd_wrapper.h"
#include "v2_1/iusb_device_interface.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;

namespace OHOS {
namespace USB {
namespace UsbGetControlTransferData {

sptr<OHOS::HDI::Usb::V2_1::IUsbDeviceInterface> g_usbDeviceInterface = nullptr;
void UsbGetControlTransferDataTest::SetUpTestCase(void)
{
    g_usbDeviceInterface = OHOS::HDI::Usb::V2_1::IUsbDeviceInterface::Get();
    if (g_usbDeviceInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbDeviceInterface::Get() failed.", __func__);
        exit(0);
    }
}

void UsbGetControlTransferDataTest::TearDownTestCase(void) {}

void UsbGetControlTransferDataTest::SetUp(void) {}

void UsbGetControlTransferDataTest::TearDown(void) {}

/**
 * @tc.name: UsbGetControlTransferData001
 * @tc.desc: Test functions to GetControlTransferData
 * @tc.desc: int32_t GetControlTransferData(int32_t eventId, std::vector<uint8_t> &data);
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbGetControlTransferDataTest, UsbGetControlTransferData001, TestSize.Level1)
{
    std::vector<uint8_t> data;
    auto ret = g_usbDeviceInterface->GetControlTransferData(ACT_CUSTOMCONTROLREQUEST, data);
    HDF_LOGI("UsbGetControlTransferDataTest:: Line:%{public}d GetControlTransferData result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbGetControlTransferData002
 * @tc.desc: Test functions to GetControlTransferData
 * @tc.desc: 正向测试：参数正确
 * @tc.desc: 测试返回数据
 * @tc.type: FUNC
 */
HWTEST_F(UsbGetControlTransferDataTest, UsbGetControlTransferData002, TestSize.Level1)
{
    std::vector<uint8_t> data;
    auto ret = g_usbDeviceInterface->GetControlTransferData(ACT_CUSTOMCONTROLREQUEST, data);
    HDF_LOGI("UsbGetControlTransferDataTest:: Line:%{public}d GetControlTransferData result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    EXPECT_FALSE(data.empty());
    HDF_LOGI("UsbGetControlTransferDataTest:: Line:%{public}d data size=%{public}zu", __LINE__, data.size());
}

} // UsbGetControlTransferData
} // USB
} // OHOS