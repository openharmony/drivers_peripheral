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

#include "usbd_async_bulk_transfer_test.h"
#include "libusb_adapter.h"

#include <iostream>
#include <vector>
#include <hdf_base.h>

#include "UsbSubscriberTest.h"
#include "usbd_type.h"
#include "usbd_wrapper.h"
#include "v1_2/iusb_interface.h"

constexpr uint8_t INTERFACEID_OK = 0;
constexpr uint32_t MAX_BUFFER_LENGTH = 0x0100U;
constexpr int32_t ASHMEM_MAX_SIZE = 1024;
constexpr int32_t ASYNC_TRANSFER_TIME_OUT = 1000;
constexpr int32_t ENDPOINT_ADDRESS_IN = 0x81; // device-to-host
constexpr int32_t ENDPOINT_ADDRESS_OUT = 0x1; // host-to-device

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace OHOS::HDI::Usb::V1_2;
using OHOS::HDI::Usb::V1_2::USBTransferInfo;

namespace OHOS::USB::UsbdAsyncBulkTransfer {

UsbDev UsbdAsyncBulkTransferTest::dev_ = {0, 0};
sptr<UsbSubscriberTest> UsbdAsyncBulkTransferTest::subscriber_ = nullptr;
sptr<OHOS::HDI::Usb::V1_2::IUsbInterface> g_usbInterface = nullptr;

int32_t InitAshmemOne(sptr<Ashmem> &asmptr, int32_t asmSize, uint8_t rflg)
{
    asmptr = Ashmem::CreateAshmem("ttashmem000", asmSize);
    if (asmptr == nullptr) {
        HDF_LOGE("InitAshmemOne CreateAshmem failed");
        return HDF_FAILURE;
    }

    asmptr->MapReadAndWriteAshmem();

    if (rflg == 0) {
        uint8_t tdata[ASHMEM_MAX_SIZE];
        int32_t offset = 0;
        int32_t tlen = 0;

        int32_t retSafe = memset_s(tdata, sizeof(tdata), 'Y', ASHMEM_MAX_SIZE);
        if (retSafe != EOK) {
            HDF_LOGE("InitAshmemOne memset_s failed");
            return HDF_FAILURE;
        }
        while (offset < asmSize) {
            tlen = (asmSize - offset) < ASHMEM_MAX_SIZE ? (asmSize - offset) : ASHMEM_MAX_SIZE;
            asmptr->WriteToAshmem(tdata, tlen, offset);
            offset += tlen;
        }
    }
    return HDF_SUCCESS;
}

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbdAsyncBulkTransferTest::SetUpTestCase(void)
{
    std::cout << "Please connect the device that supports bulk(rk3568), and press Enter." << std::endl;
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != EOF);

    SubscriberEvent();
}

void UsbdAsyncBulkTransferTest::TearDownTestCase(void)
{
    g_usbInterface->UnbindUsbdSubscriber(subscriber_);
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    auto ret = g_usbInterface->CloseDevice(dev_);
    HDF_LOGI("UsbdAsyncBulkTransferTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdAsyncBulkTransferTest::SetUp(void) {}

void UsbdAsyncBulkTransferTest::TearDown(void) {}

void UsbdAsyncBulkTransferTest::SubscriberEvent()
{
    g_usbInterface = OHOS::HDI::Usb::V1_2::IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }

    subscriber_ = new UsbSubscriberTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubscriberTest new failed.", __func__);
        exit(0);
    }
    if (g_usbInterface->BindUsbdSubscriber(subscriber_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber_ failed", __func__);
        exit(0);
    }

    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    int32_t ret = g_usbInterface->OpenDevice(dev_);
    HDF_LOGI("UsbdAsyncBulkTransferTest:: %{public}d OpenDevice=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: BulkRead001
 * @tc.desc: Test functions to UsbSubmitTransfer
 * @tc.desc: int32_t UsbSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *           const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem);
 * @tc.desc: Positive test: bulk read, The parameters are correct.
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncBulkTransferTest, BulkRead001, TestSize.Level1)
{
    HDF_LOGI("Case Start: BulkRead001");
    struct UsbDev dev = dev_;
    struct USBTransferInfo info = {
        .endpoint = ENDPOINT_ADDRESS_IN,
        .flags = 0,
        .type = LIBUSB_TRANSFER_TYPE_BULK,
        .timeOut = ASYNC_TRANSFER_TIME_OUT,
        .length = MAX_BUFFER_LENGTH,
        .userData = 0,
        .numIsoPackets = 0,
    };
    sptr<UsbdTransferCallbackTest> usbdBulkCallback = new UsbdTransferCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdTransferCallbackTest new failed.", __func__);
        exit(0);
    }
    sptr<Ashmem> ashmem;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    uint8_t rflg = 1;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    auto ret = g_usbInterface->ClaimInterface(dev, INTERFACEID_OK, 1);
    HDF_LOGI("UsbdAsyncBulkTransferTest::BulkRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ret = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
    HDF_LOGI("UsbdAsyncBulkTransferTest::BulkRead001 %{public}d UsbSubmitTransfer=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
    HDF_LOGI("Case End: BulkRead001");
}

/**
 * @tc.name: BulkWrite001
 * @tc.desc: Test functions to UsbSubmitTransfer
 * @tc.desc: int32_t UsbSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *           const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem);
 * @tc.desc: Positive test: bulk write, The parameters are correct.
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncBulkTransferTest, BulkWrite001, TestSize.Level1)
{
    HDF_LOGI("Case Start: BulkWrite001");
    struct UsbDev dev = dev_;
    struct USBTransferInfo info = {
        .endpoint = ENDPOINT_ADDRESS_OUT,
        .flags = 0,
        .type = LIBUSB_TRANSFER_TYPE_BULK,
        .timeOut = ASYNC_TRANSFER_TIME_OUT,
        .length = MAX_BUFFER_LENGTH,
        .userData = 0,
        .numIsoPackets = 0,
    };
    sptr<UsbdTransferCallbackTest> usbdBulkCallback = new UsbdTransferCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdTransferCallbackTest new failed.", __func__);
        exit(0);
    }
    sptr<Ashmem> ashmem;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    uint8_t rflg = 0;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    auto ret = g_usbInterface->ClaimInterface(dev, INTERFACEID_OK, 1);
    HDF_LOGI("UsbdAsyncBulkTransferTest::BulkWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ret = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
    if (ret == LIBUSB_ERROR_NOT_SUPPORTED) {
        ret = 0;
    }
    HDF_LOGI("UsbdAsyncBulkTransferTest::BulkWrite001 %{public}d UsbSubmitTransfer=%{public}d", __LINE__, ret);
    if (ret == 0) {
        EXPECT_TRUE(true);
    } else {
        EXPECT_TRUE(false);
    }
    HDF_LOGI("Case End: BulkWrite001");
}

/**
 * @tc.name: CancelBulkTransfer001
 * @tc.desc: Test functions to UsbCancelTransfer
 * @tc.desc: int32_t UsbCancelTransfer(const UsbDev &dev, const int32_t endpoint);
 * @tc.desc: Positive test: the parameters are correct.
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncBulkTransferTest, CancelBulkTransfer001, TestSize.Level1)
{
    HDF_LOGI("Case Start: CancelBulkTransfer001");
    struct UsbDev dev = dev_;
    struct USBTransferInfo info = {
        .endpoint = ENDPOINT_ADDRESS_IN,
        .flags = 0,
        .type = LIBUSB_TRANSFER_TYPE_BULK,
        .timeOut = 0,
        .length = MAX_BUFFER_LENGTH,
        .userData = 0,
        .numIsoPackets = 0,
    };
    sptr<UsbdTransferCallbackTest> usbdBulkCallback = new UsbdTransferCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdTransferCallbackTest new failed.", __func__);
        exit(0);
    }
    sptr<Ashmem> ashmem;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    uint8_t rflg = 0;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    auto ret = g_usbInterface->ClaimInterface(dev, INTERFACEID_OK, 1);
    HDF_LOGI("UsbdAsyncBulkTransferTest::CancelBulkTransfer001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    int32_t submitTransferRet = 0;
    for (int i = 0; i < 10; i++) {
        submitTransferRet = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
        HDF_LOGI("UsbdAsyncBulkTransferTest::CancelBulkTransfer001 %{public}d UsbSubmitTransfer=%{public}d",
            __LINE__, submitTransferRet);
    }
    auto cancelTransferRet = g_usbInterface->UsbCancelTransfer(dev, ENDPOINT_ADDRESS_IN);
    if (cancelTransferRet == LIBUSB_ERROR_NOT_SUPPORTED) {
        cancelTransferRet = 0;
    }
    HDF_LOGI("UsbdAsyncBulkTransferTest::CancelBulkTransfer001 %{public}d UsbCancelTransfer=%{public}d",
        __LINE__, cancelTransferRet);
    if (cancelTransferRet == 0 || cancelTransferRet == -5) {
        EXPECT_TRUE(true);
    } else {
        EXPECT_TRUE(false);
    }
    HDF_LOGI("Case End: CancelBulkTransfer001");
}

/**
 * @tc.name: CancelBulkTransfer002
 * @tc.desc: Test functions to UsbCancelTransfer
 * @tc.desc: int32_t UsbCancelTransfer(const UsbDev &dev, const int32_t endpoint);
 * @tc.desc: Positive test: the parameters are correct.
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncBulkTransferTest, CancelBulkTransfer002, TestSize.Level1)
{
    HDF_LOGI("Case Start: CancelBulkTransfer001");
    struct UsbDev dev = dev_;
    struct USBTransferInfo info = {
        .endpoint = ENDPOINT_ADDRESS_OUT,
        .flags = 0,
        .type = LIBUSB_TRANSFER_TYPE_BULK,
        .timeOut = 0,
        .length = MAX_BUFFER_LENGTH,
        .userData = 0,
        .numIsoPackets = 0,
    };
    sptr<UsbdTransferCallbackTest> usbdBulkCallback = new UsbdTransferCallbackTest();
    if (usbdBulkCallback == nullptr) {
        HDF_LOGE("%{public}s:UsbdTransferCallbackTest new failed.", __func__);
        exit(0);
    }
    sptr<Ashmem> ashmem;
    int32_t asmSize = MAX_BUFFER_LENGTH;
    uint8_t rflg = 0;
    (void)InitAshmemOne(ashmem, asmSize, rflg);
    auto ret = g_usbInterface->ClaimInterface(dev, INTERFACEID_OK, 1);
    HDF_LOGI("UsbdAsyncBulkTransferTest::CancelBulkTransfer002 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    int32_t submitTransferRet = 0;
    for (int i = 0; i < 10; i++) {
        submitTransferRet = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
        HDF_LOGI("UsbdAsyncBulkTransferTest::CancelBulkTransfer002 %{public}d UsbSubmitTransfer=%{public}d",
            __LINE__, submitTransferRet);
    }
    auto cancelTransferRet = g_usbInterface->UsbCancelTransfer(dev, ENDPOINT_ADDRESS_OUT);
    if (cancelTransferRet == LIBUSB_ERROR_NOT_SUPPORTED) {
        cancelTransferRet = 0;
    }
    HDF_LOGI("UsbdAsyncBulkTransferTest::CancelBulkTransfer002 %{public}d UsbCancelTransfer=%{public}d",
        __LINE__, cancelTransferRet);
    if (cancelTransferRet == 0 || cancelTransferRet == -5) {
        EXPECT_TRUE(true);
    } else {
        EXPECT_TRUE(false);
    }
    HDF_LOGI("Case End: CancelBulkTransfer002");
}

/**
 * @tc.name: CancelBulkTransfer003
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
        const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test: error device busnum and devaddr
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncBulkTransferTest, CancelBulkTransfer003, TestSize.Level1)
{
    HDF_LOGI("Case Start: CancelBulkTransfer003");
    std::shared_ptr<LibusbAdapter> adapter = LibusbAdapter::GetInstance();
    UsbDev device_ = {0, 0};
    int errEndPoint = 0x12;

    int32_t ret = adapter->AsyncCancelTransfer(device_, errEndPoint);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: CancelBulkTransfer003");
}

/**
 * @tc.name: CancelBulkTransfer004
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
        const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test: device exit and transferList is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncBulkTransferTest, CancelBulkTransfer004, TestSize.Level1)
{
    HDF_LOGI("Case Start: CancelBulkTransfer004");
    std::shared_ptr<LibusbAdapter> adapter = LibusbAdapter::GetInstance();
    UsbDev device_ = dev_;
    int errEndPoint = 0x13;

    int32_t ret = adapter->AsyncCancelTransfer(device_, errEndPoint);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: CancelBulkTransfer004");
}

/**
 * @tc.name: AsyncSubmitTransfer001
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *     const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test: Wrong device bus number and bus address
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncBulkTransferTest, AsyncSubmitTransfer001, TestSize.Level1)
{
    HDF_LOGI("Case Start: AsyncSubmitTransfer001");
    std::shared_ptr<LibusbAdapter> adapter = LibusbAdapter::GetInstance();
    UsbDev device_ = {1, 2};
    USBTransferInfo usbInfo_;

    int32_t ret = adapter->AsyncSubmitTransfer(device_, usbInfo_, nullptr, nullptr);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: AsyncSubmitTransfer001");
}

/**
 * @tc.name: AsyncSubmitTransfer002
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *    const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test: data transfer length is zero
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncBulkTransferTest, AsyncSubmitTransfer002, TestSize.Level1)
{
    HDF_LOGI("Case Start: AsyncSubmitTransfer002");
    std::shared_ptr<LibusbAdapter> adapter = LibusbAdapter::GetInstance();
    UsbDev device_ = dev_;
    USBTransferInfo usbInfo_;
    usbInfo_.length = 0;

    int32_t ret = adapter->AsyncSubmitTransfer(device_, usbInfo_, nullptr, nullptr);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: AsyncSubmitTransfer002");
}

/**
 * @tc.name: AsyncSubmitTransfer003
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *    const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test, use error endpoint
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncBulkTransferTest, AsyncSubmitTransfer003, TestSize.Level1)
{
    HDF_LOGI("Case Start: AsyncSubmitTransfer003");
    std::shared_ptr<LibusbAdapter> adapter = LibusbAdapter::GetInstance();
    UsbDev device_ = dev_;
    USBTransferInfo usbInfo_;
    usbInfo_.endpoint = ENDPOINT_ADDRESS_IN - 0x09;
    usbInfo_.flags = 0;
    usbInfo_.type = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS;
    usbInfo_.timeOut = 1000;
    usbInfo_.userData = 0;
    usbInfo_.numIsoPackets = 0;
    usbInfo_.length = 0;

    int32_t ret = adapter->AsyncSubmitTransfer(device_, usbInfo_, nullptr, nullptr);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: AsyncSubmitTransfer003");
}
} // namespace OHOS::USB::UsbdAsyncBulkTransfer
