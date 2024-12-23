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

#include "usbd_async_transfer_test.h"
#include "libusb_adapter.h"

#include <iostream>
#include <vector>
#include <hdf_base.h>

#include "UsbSubscriberTest.h"
#include "usbd_type.h"
#include "usbd_wrapper.h"
#include "v1_2/iusb_interface.h"

const int SLEEP_TIME = 3;
const uint8_t INTERFACEID_OK = 0;
const uint32_t MAX_BUFFER_LENGTH = 0x0100U;
const int32_t ASHMEM_MAX_SIZE = 1024;
const int32_t ASYNC_TRANSFER_TIME_OUT = 1000;
const int32_t  ENDPOINT_ADDRESS_IN = 0x81; // device-to-host
const int32_t ENDPOINT_ADDRESS_OUT = 0x1; // host-to-device
const int32_t ISOCHRONOUS_PACKETS = 2;

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace OHOS::HDI::Usb::V1_2;
using OHOS::HDI::Usb::V1_2::USBTransferInfo;

namespace OHOS::USB::UsbdAsyncTransfer {
UsbDev UsbdAsyncTransferTest::dev_ = {0, 0};
sptr<UsbSubscriberTest> UsbdAsyncTransferTest::subscriber_ = nullptr;
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

void UsbdAsyncTransferTest::SetUpTestCase(void)
{
    std::cout << "Please connect the device that supports interruption, and press Enter." << std::endl;
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != EOF);

    SubscriberEvent();
}

void UsbdAsyncTransferTest::TearDownTestCase(void)
{
    SubscriberEvent();
    g_usbInterface->UnbindUsbdSubscriber(subscriber_);
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    auto ret = g_usbInterface->CloseDevice(dev_);
    HDF_LOGI("UsbdAsyncTransferTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdAsyncTransferTest::SetUp(void) {}

void UsbdAsyncTransferTest::TearDown(void) {}

void UsbdAsyncTransferTest::SubscriberEvent()
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
    ret = g_usbInterface->OpenDevice(dev_);
    HDF_LOGI("UsbdAsyncTransferTest:: %{public}d OpenDevice=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: InterruptRead001
 * @tc.desc: Test functions to UsbSubmitTransfer
 * @tc.desc: int32_t UsbSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *           const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem);
 * @tc.desc: Positive test: interrupt read, The parameters are correct.
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, InterruptRead001, TestSize.Level1)
{
    HDF_LOGI("Case Start: InterruptRead001");
    struct UsbDev dev = dev_;
    struct USBTransferInfo info = {
        .endpoint = ENDPOINT_ADDRESS_IN,
        .flags = 0,
        .type = LIBUSB_TRANSFER_TYPE_INTERRUPT,
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
    HDF_LOGI("UsbdAsyncTransferTest::InterruptRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ret = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
    if (ret == LIBUSB_ERROR_NOT_SUPPORTED) {
        ret = 0;
    }
    HDF_LOGE("UsbdAsyncTransferTest::InterruptRead001 %{public}d UsbSubmitTransfer=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
    HDF_LOGI("Case End: InterruptRead001");
}

/**
 * @tc.name: InterruptWrite001
 * @tc.desc: Test functions to UsbSubmitTransfer
 * @tc.desc: int32_t UsbSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *           const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem);
 * @tc.desc: Positive test: interrupt write, The parameters are correct.
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, InterruptWrite001, TestSize.Level1)
{
    HDF_LOGI("Case Start: InterruptWrite001");
    struct UsbDev dev = dev_;
    struct USBTransferInfo info = {
        .endpoint = ENDPOINT_ADDRESS_OUT,
        .flags = 0,
        .type = LIBUSB_TRANSFER_TYPE_INTERRUPT,
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
    HDF_LOGI("UsbdAsyncTransferTest::InterruptWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ret = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
    HDF_LOGI("UsbdAsyncTransferTest::InterruptWrite001 %{public}d UsbSubmitTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: InterruptWrite001");
}

/**
 * @tc.name: IsochronousRead001
 * @tc.desc: Test functions to UsbSubmitTransfer
 * @tc.desc: int32_t UsbSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *           const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem);
 * @tc.desc: Positive test: isochronous read, The parameters are correct.
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, IsochronousRead001, TestSize.Level1)
{
    HDF_LOGI("Case Start: IsochronousRead001");
    struct UsbDev dev = dev_;
    struct USBTransferInfo info = {
        .endpoint = ENDPOINT_ADDRESS_IN,
        .flags = 0,
        .type = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS,
        .timeOut = ASYNC_TRANSFER_TIME_OUT,
        .length = MAX_BUFFER_LENGTH,
        .userData = 0,
        .numIsoPackets = ISOCHRONOUS_PACKETS,
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
    HDF_LOGI("UsbdAsyncTransferTest::IsochronousRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ret = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
    HDF_LOGI("UsbdAsyncTransferTest::IsochronousRead001 %{public}d UsbSubmitTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: IsochronousRead001");
}

/**
 * @tc.name: IsochronousWrite001
 * @tc.desc: Test functions to UsbSubmitTransfer
 * @tc.desc: int32_t UsbSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *           const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem);
 * @tc.desc: Positive test: isochronous write, The parameters are correct.
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, IsochronousWrite001, TestSize.Level1)
{
    HDF_LOGI("Case Start: IsochronousWrite001");
    struct UsbDev dev = dev_;
    struct USBTransferInfo info = {
        .endpoint = ENDPOINT_ADDRESS_OUT,
        .flags = 0,
        .type = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS,
        .timeOut = ASYNC_TRANSFER_TIME_OUT,
        .length = MAX_BUFFER_LENGTH,
        .userData = 0,
        .numIsoPackets = ISOCHRONOUS_PACKETS,
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
    HDF_LOGI("UsbdAsyncTransferTest::IsochronousWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ret = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
    HDF_LOGI("UsbdAsyncTransferTest::IsochronousWrite001 %{public}d UsbSubmitTransfer=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: IsochronousWrite001");
}

/**
 * @tc.name: BulkRead001
 * @tc.desc: Test functions to UsbSubmitTransfer
 * @tc.desc: int32_t UsbSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *           const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem);
 * @tc.desc: Positive test: bulk read, The parameters are correct.
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, BulkRead001, TestSize.Level1)
{
    std::cout << "Please disconnect the currently connected device, then connect bulk device(rk3568), " \
    "and press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    SubscriberEvent();

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
    HDF_LOGI("UsbdAsyncTransferTest::BulkRead001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ret = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
    if (ret == LIBUSB_ERROR_NOT_SUPPORTED) {
        ret = 0;
    }
    HDF_LOGI("UsbdAsyncTransferTest::BulkRead001 %{public}d UsbSubmitTransfer=%{public}d", __LINE__, ret);
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
HWTEST_F(UsbdAsyncTransferTest, BulkWrite001, TestSize.Level1)
{
    HDF_LOGI("Case Start: BulkWrite001");
    struct UsbDev dev = dev_;
    struct USBTransferInfo info = {
        .endpoint = 0x1,
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
    HDF_LOGI("UsbdAsyncTransferTest::BulkWrite001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    ret = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
    if (ret == LIBUSB_ERROR_NOT_SUPPORTED) {
        ret = 0;
    }
    HDF_LOGI("UsbdAsyncTransferTest::BulkWrite001 %{public}d UsbSubmitTransfer=%{public}d", __LINE__, ret);
    EXPECT_EQ(ret, 0);
    HDF_LOGI("Case End: BulkWrite001");
}

/**
 * @tc.name: UsbCancelTransfer001
 * @tc.desc: Test functions to UsbCancelTransfer
 * @tc.desc: int32_t UsbCancelTransfer(const UsbDev &dev, const int32_t endpoint);
 * @tc.desc: Positive test: the parameters are correct.
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, CancelTransfer001, TestSize.Level1)
{
    HDF_LOGI("Case Start: CancelTransfer001");
    struct UsbDev dev = dev_;
    struct USBTransferInfo info = {
        .endpoint = 0x1,
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
    HDF_LOGI("UsbdAsyncTransferTest::CancelTransfer001 %{public}d ClaimInterface=%{public}d", __LINE__, ret);
    int32_t submitTransferRet = 0;
    for (int i = 0; i < 10; i++) {
        submitTransferRet = g_usbInterface->UsbSubmitTransfer(dev, info, usbdBulkCallback, ashmem);
        HDF_LOGI("UsbdAsyncTransferTest::CancelTransfer001 %{public}d UsbSubmitTransfer=%{public}d",
            __LINE__, submitTransferRet);
    }
    auto cancelTransferRet = g_usbInterface->UsbCancelTransfer(dev, ENDPOINT_ADDRESS_IN);
    if (cancelTransferRet == LIBUSB_ERROR_NOT_SUPPORTED) {
        cancelTransferRet = 0;
    }
    HDF_LOGI("UsbdAsyncTransferTest::CancelTransfer001 %{public}d UsbCancelTransfer=%{public}d",
        __LINE__, cancelTransferRet);
    if (cancelTransferRet == 0 || cancelTransferRet == -5) {
        EXPECT_TRUE(true);
    } else {
        EXPECT_TRUE(false);
    }
    HDF_LOGI("Case Start: CancelTransfer001");
}

/**
 * @tc.name: AsyncSubmitTransfer008
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *    const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test: No device connection
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, AsyncSubmitTransfer008, TestSize.Level1)
{
    std::cout << "Please disconnect the currently connected device, press enter to continue" << std::endl;
    
    int32_t c;
    do {
        c = getchar();
    } while (c != '\n' && c != EOF);

    HDF_LOGI("Case Start: AsyncSubmitTransfer008");
    std::shared_ptr<LibusbAdapter> adapter = LibusbAdapter::GetInstance();
    UsbDev device_ = {1, 2};
    USBTransferInfo usbInfo_;

    int32_t ret = adapter->AsyncSubmitTransfer(device_, usbInfo_, nullptr, nullptr);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case Start: AsyncSubmitTransfer008");
}

/**
 * @tc.name: AsyncSubmitTransfer009
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *     const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test: Wrong device bus number and bus address
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, AsyncSubmitTransfer009, TestSize.Level1)
{
    std::cout << "Please connect the device, press enter to continue" << std::endl;
    
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    
    SubscriberEvent();
    HDF_LOGI("Case Start: AsyncSubmitTransfer009");
    std::shared_ptr<LibusbAdapter> adapter = LibusbAdapter::GetInstance();
    UsbDev device_ = {1, 2};
    USBTransferInfo usbInfo_;

    int32_t ret = adapter->AsyncSubmitTransfer(device_, usbInfo_, nullptr, nullptr);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: AsyncSubmitTransfer009");
}

/**
 * @tc.name: AsyncSubmitTransfer010
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *    const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test: data transfer length is zero
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, AsyncSubmitTransfer010, TestSize.Level1)
{
    HDF_LOGI("Case Start: AsyncSubmitTransfer010");
    std::shared_ptr<LibusbAdapter> adapter = LibusbAdapter::GetInstance();
    UsbDev device_ = dev_;
    USBTransferInfo usbInfo_;
    usbInfo_.length = 0;

    int32_t ret = adapter->AsyncSubmitTransfer(device_, usbInfo_, nullptr, nullptr);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: AsyncSubmitTransfer010");
}

/**
 * @tc.name: AsyncSubmitTransfer011
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
 *    const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test, use error endpoint
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, AsyncSubmitTransfer011, TestSize.Level1)
{
    HDF_LOGI("Case Start: AsyncSubmitTransfer011");
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
    HDF_LOGI("Case End: AsyncSubmitTransfer011");
}

/**
 * @tc.name: AsyncCancelTransfer012
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
        const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test: error device busnum and devaddr
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, AsyncCancelTransfer012, TestSize.Level1)
{
    HDF_LOGI("Case Start: AsyncSubmitTransfer012");
    std::shared_ptr<LibusbAdapter> adapter = LibusbAdapter::GetInstance();
    UsbDev device_ = {0, 0};
    int errEndPoint = 0x12;

    int32_t ret = adapter->AsyncCancelTransfer(device_, errEndPoint);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: AsyncSubmitTransfer012");
}

/**
 * @tc.name: AsyncCancelTransfer013
 * @tc.desc: Test functions to int32_t AsyncSubmitTransfer(const UsbDev &dev, const USBTransferInfo &info,
        const sptr<IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
 * @tc.desc: negative test: device exit and transferList is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UsbdAsyncTransferTest, AsyncCancelTransfer013, TestSize.Level1)
{
    HDF_LOGI("Case Start: AsyncSubmitTransfer013");
    std::shared_ptr<LibusbAdapter> adapter = LibusbAdapter::GetInstance();
    UsbDev device_ = dev_;
    int errEndPoint = 0x13;

    int32_t ret = adapter->AsyncCancelTransfer(device_, errEndPoint);
    EXPECT_NE(ret, 0);
    HDF_LOGI("Case End: AsyncSubmitTransfer013");
}

} // namespace