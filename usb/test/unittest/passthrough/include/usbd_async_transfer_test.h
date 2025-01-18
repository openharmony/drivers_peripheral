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
#ifndef USBD_ASYNC_TRANSFER_TEST_H
#define USBD_ASYNC_TRANSFER_TEST_H

#include <gtest/gtest.h>

#include "UsbSubTest.h"
#include "v2_0/iusbd_subscriber.h"
#include "v2_0/usb_types.h"
#include "v2_0/iusbd_transfer_callback.h"
#include "hdf_log.h"
#include "securec.h"

using OHOS::HDI::Usb::V2_0::UsbDev;

namespace OHOS {
namespace USB {
namespace UsbdAsyncTransfer {
class UsbdAsyncTransferTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static void SubscriberEvent();

    static UsbDev dev_;
    static OHOS::sptr<OHOS::USB::UsbSubTest> subscriber_;
};

class UsbdTransferCallbackTest : public OHOS::HDI::Usb::V2_0::IUsbdTransferCallback {
public:
    UsbdTransferCallbackTest() = default;
    ~UsbdTransferCallbackTest() = default;
    int32_t OnTransferWriteCallback(int32_t status, int32_t actLength,
        const std::vector<OHOS::HDI::Usb::V2_0::UsbIsoPacketDescriptor>& descs, const uint64_t userData) override
    {
        return 0;
    }
    int32_t OnTransferReadCallback(int32_t status, int32_t actLength,
         const std::vector<OHOS::HDI::Usb::V2_0::UsbIsoPacketDescriptor>& descs, const uint64_t userData) override
    {
        return 0;
    }
};
} // UsbdAsyncTransfer
} // USB
} // OHOS
#endif // USBD_ASYNC_TRANSFER_TEST_H
