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
#ifndef USBD_HUB_DEVICE_TEST_H
#define USBD_HUB_DEVICE_TEST_H

#include <gtest/gtest.h>
#include "v2_0/iusb_host_interface.h"
#include "v2_0/usb_types.h"
#include "v2_0/iusbd_subscriber.h"
#include "usbd_type.h"
using OHOS::HDI::Usb::V2_0::UsbDev;

struct DevBusInfo {
    int32_t busNum;
    int32_t devAddr;
};
class UsbSubscriberTest : public OHOS::HDI::Usb::V2_0::IUsbdSubscriber {
public:
    UsbSubscriberTest() = default;
    ~UsbSubscriberTest() = default;
    int32_t DeviceEvent(const OHOS::HDI::Usb::V2_0::USBDeviceInfo &info) override
    {
        if (info.status == ACT_UPDEVICE || info.status == ACT_DOWNDEVICE) {
            return 0;
        }
        busNum_ = info.busNum;
        devAddr_ = info.devNum;
        DevBusInfo busInfo;
        busInfo.busNum = busNum_;
        busInfo.devAddr = devAddr_;
        busInfos.push_back(busInfo);
        return 0;
    }
    int32_t PortChangedEvent(const OHOS::HDI::Usb::V2_0::PortInfo &info) override
    {
        return 0;
    };

    int32_t busNum_ = 0;
    int32_t devAddr_ = 0;
    std::vector<DevBusInfo> busInfos;
};

namespace {
class UsbdHubDeviceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static UsbDev dev_;
    static UsbDev hubDev_;
    static OHOS::sptr<UsbSubscriberTest> subscriber_;
};
} // namespace
#endif // USBD_HUB_DEVICE_TEST_H
