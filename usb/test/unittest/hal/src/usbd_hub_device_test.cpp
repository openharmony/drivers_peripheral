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

#include "usbd_hub_device_test.h"

#include <iostream>
#include <vector>

#include "hdf_log.h"

#include "v2_0/iusb_host_interface.h"
#include "v2_0/usb_types.h"
using namespace testing::ext;
using namespace OHOS;
using namespace std;

using namespace OHOS::HDI::Usb::V2_0;

UsbDev UsbdHubDeviceTest::dev_ = {0, 0};
UsbDev UsbdHubDeviceTest::hubDev_ = {0, 0};
sptr<UsbSubscriberTest> UsbdHubDeviceTest::subscriber_ = nullptr;
const std::string SERVICE_NAME = "usb_host_interface_service";
namespace {
sptr<OHOS::HDI::Usb::V2_0::IUsbHostInterface> g_usbInterface = nullptr;

void UsbdHubDeviceTest::SetUpTestCase(void)
{
    g_usbInterface = OHOS::HDI::Usb::V2_0::IUsbHostInterface::Get(SERVICE_NAME, true);
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }

    subscriber_ = new UsbSubscriberTest();
    if (g_usbInterface->BindUsbdHostSubscriber(subscriber_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber_ failed", __func__);
        exit(0);
    }
    for (size_t i = 0; i < subscriber_->busInfos.size(); i++) {
        struct UsbDev dev = {subscriber_->busInfos[i].busNum, subscriber_->busInfos[i].devAddr};
        g_usbInterface->OpenDevice(dev);
        std::vector<uint8_t> rawData;
        auto ret = g_usbInterface->GetRawDescriptor(dev, rawData);
        ASSERT_EQ(0, ret);
        uint32_t deviceDescriptorSize = sizeof(UsbdDeviceDescriptor);
        if (rawData.size() < deviceDescriptorSize) {
            HDF_LOGE("%{public}s: rawData failed", __func__);
            exit(0);
            return ;
        }
    
        UsbdDeviceDescriptor deviceDescriptor = *(reinterpret_cast<const UsbdDeviceDescriptor *>(rawData.data()));
        if (deviceDescriptor.bLength != deviceDescriptorSize) {
            HDF_LOGE("UsbdDeviceDescriptor size error");
            exit(0);
        }
        if (deviceDescriptor.bDeviceClass != 9) {
            dev_ = dev;
        } else {
            hubDev_ = dev;
        }
    }

    std::cout << "please connect hub device, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

void UsbdHubDeviceTest::TearDownTestCase(void)
{
    g_usbInterface->UnbindUsbdHostSubscriber(subscriber_);
}

void UsbdHubDeviceTest::SetUp(void) {}

void UsbdHubDeviceTest::TearDown(void) {}

/**
 * @tc.name: hub device
 * @tc.desc: Test functions to hub device hot plug
 * @tc.desc: int32_t;
 * @tc.desc: 正向测试：参数正确
 * @tc.type: FUNC
 */
HWTEST_F(UsbdHubDeviceTest, UsbdHubDevicehotPlug001, TestSize.Level1)
{
    int32_t ret = 1;
    if (hubDev_.busNum != 0 && hubDev_.devAddr != 0) {
        ret = 0;
    }
    HDF_LOGI("UsbdHubDeviceTest:: Line:%{public}d hub device busNum =%{public}d", __LINE__, hubDev_.busNum);
    EXPECT_EQ(0, ret);
}

} // namespace
