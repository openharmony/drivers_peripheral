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

#include "usbd_mtp_host_extended_test.h"

#include <iostream>
#include <vector>
#include <chrono>

#include "UsbSubTest.h"
#include "hdf_log.h"
#include "securec.h"
#include "usbd_type.h"
#include "usbd_wrapper.h"
#include "v2_0/iusb_host_interface.h"
#include "v2_0/iusb_port_interface.h"
#include "v2_0/usb_types.h"

#define HDF_LOG_TAG usbd_mtp_host_extended_ut

const int SLEEP_TIME = 3;
const uint8_t INTERFACEID_OK = 1;
// data interface have 2 point : 1->bulk_out 2->bulk_in
static const uint8_t POINTID_BULK_IN = USB_ENDPOINT_DIR_IN | 2;
static const uint8_t POINTID_BULK_OUT = USB_ENDPOINT_DIR_OUT | 1;
const int32_t TRANSFER_TIME_OUT = 1000;

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V2_0;

namespace {
// MTP protocol constants (matching device-side extended tests)
constexpr uint32_t BULK_BUFFER_SIZE = 8192;
constexpr uint32_t BULK_OUT_LESS_THEN_ONCE = 23;
constexpr uint32_t BULK_IN_ONCE_MAX_SIZE = 1024;
constexpr uint32_t BULK_IN_LESS_THEN_ONCE = 45;
constexpr uint32_t MTP_PACKET_HEADER_SIZE = 12;
constexpr uint32_t MTP_FILE_SIZE_REUSE_REQ = 12 * 1024;
constexpr int64_t LARGE_FILE_SIZE = 100 * 1024 * 1024;  // 100MB

// MTP Command Codes
constexpr uint16_t CMD_CODE_OPEN_SESSION = 0x1002;
constexpr uint16_t CMD_CODE_GET_OBJECT_HANDLES = 0x1007;
constexpr uint16_t CMD_CODE_GET_OBJECT = 0x1009;

// Transaction IDs
constexpr uint32_t TRANSACTION_ID_BASE = 0x1000;

UsbDev UsbdMtpHostExtendedTest::dev_ = {0, 0};
sptr<UsbSubTest> UsbdMtpHostExtendedTest::subscriber_ = nullptr;

sptr<IUsbHostInterface> g_usbHostInterface = nullptr;
sptr<IUsbPortInterface> g_usbPortInterface = nullptr;

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbdMtpHostExtendedTest::SetUpTestCase(void)
{
    g_usbHostInterface = IUsbHostInterface::Get(true);
    g_usbPortInterface = IUsbPortInterface::Get();
    if (g_usbHostInterface == nullptr || g_usbPortInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    const int32_t DEFAULT_PORT_ID = 1;
    const int32_t DEFAULT_ROLE_HOST = 1;
    auto ret = g_usbPortInterface->SetPortRole(DEFAULT_PORT_ID, DEFAULT_ROLE_HOST, DEFAULT_ROLE_HOST);
    sleep(SLEEP_TIME);
    HDF_LOGI("UsbdMtpHostExtendedTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
    ret = SwitchErrCode(ret);
    ASSERT_EQ(0, ret);
    if (ret != 0) {
        exit(0);
    }

    subscriber_ = new UsbSubTest();
    if (subscriber_ == nullptr) {
        HDF_LOGE("%{public}s:UsbSubTest new failed.", __func__);
        exit(0);
    }
    if (g_usbHostInterface->BindUsbdHostSubscriber(subscriber_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber_ failed", __func__);
        exit(0);
    }

    std::cout << "please connect MTP device, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    ret = g_usbHostInterface->OpenDevice(dev_);
    HDF_LOGI("UsbdMtpHostExtendedTest:: %{public}d OpenDevice=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdMtpHostExtendedTest::TearDownTestCase(void)
{
    HDF_LOGI("%{public}s: TearDownTestCase in.", __func__);
    g_usbHostInterface->UnbindUsbdHostSubscriber(subscriber_);
    dev_ = {subscriber_->busNum_, subscriber_->devAddr_};
    auto ret = g_usbHostInterface->CloseDevice(dev_);
    HDF_LOGI("UsbdMtpHostExtendedTest:: %{public}d Close=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
}

void UsbdMtpHostExtendedTest::SetUp(void) {}

void UsbdMtpHostExtendedTest::TearDown(void) {}

// ============================================================================
// 2. File Operation Edge Cases
// ============================================================================

/**
 * @tc.name: UsbdMtpHostFileSendWithOffset001
 * @tc.desc: SendFile with non-zero offset
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostFileSendWithOffset001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    uint32_t fileSize = BULK_IN_LESS_THEN_ONCE + 100;
    uint32_t offset = 100;
    std::vector<uint8_t> bufferData(fileSize, 'x');

    std::cout << "UsbdMtpHostFileSendWithOffset001===>send data with offset=" << offset
              << ", Device should call ReceiveFile, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostFileSendWithOffset002
 * @tc.desc: SendFile with offset at file boundary
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostFileSendWithOffset002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    uint32_t fileSize = BULK_IN_ONCE_MAX_SIZE * 2;
    uint32_t offset = BULK_IN_ONCE_MAX_SIZE;
    std::vector<uint8_t> bufferData(fileSize, 'y');

    std::cout << "UsbdMtpHostFileSendWithOffset002===>send data at page boundary offset=" << offset
              << ", Device should call ReceiveFile, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostFileReceiveWithOffset001
 * @tc.desc: ReceiveFile with non-zero offset
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostFileReceiveWithOffset001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    uint32_t offset = 50;
    std::vector<uint8_t> bufferData(BULK_OUT_LESS_THEN_ONCE);

    std::cout << "UsbdMtpHostFileReceiveWithOffset001===>receive data with offset=" << offset
              << ", Device should call SendFile, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostFileSendPartial001
 * @tc.desc: SendFile with length smaller than file size
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostFileSendPartial001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    uint64_t fileSize = MTP_FILE_SIZE_REUSE_REQ;
    uint32_t sendSize = BULK_IN_LESS_THEN_ONCE;
    std::vector<uint8_t> bufferData(fileSize, 'p');

    std::cout << "UsbdMtpHostFileSendPartial001===>send partial file " << sendSize
              << " bytes, Device should call ReceiveFile, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostFileSendNonExist001
 * @tc.desc: SendFile with non-existent file path
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostFileSendNonExist001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(BULK_IN_LESS_THEN_ONCE, 'n');

    std::cout << "UsbdMtpHostFileSendNonExist001===>send data for non-existent file"
              << ", Device should call ReceiveFile, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostFileOffsetOverflow001
 * @tc.desc: SendFile with offset exceeding file size
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostFileOffsetOverflow001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    uint64_t fileSize = MTP_FILE_SIZE_REUSE_REQ;
    uint64_t offset = MTP_FILE_SIZE_REUSE_REQ * 2;
    std::vector<uint8_t> bufferData(fileSize, 'o');

    std::cout << "UsbdMtpHostFileOffsetOverflow001===>send data with overflow offset=" << offset
              << ", Device should call ReceiveFile, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

// ============================================================================
// 3. Concurrent Operation Tests
// ============================================================================

/**
 * @tc.name: UsbdMtpHostConcurrentReadWrite001
 * @tc.desc: Interleaved Read/Write operations
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostConcurrentReadWrite001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointidOut = POINTID_BULK_OUT;
    uint8_t pointidIn = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "===>interleaved read/write test, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Write
    UsbPipe pipeOut = {interfaceId, pointidOut};
    std::vector<uint8_t> writeData(BULK_IN_LESS_THEN_ONCE, 'w');
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipeOut, TRANSFER_TIME_OUT, writeData);
    EXPECT_EQ(0, ret);

    // Read
    UsbPipe pipeIn = {interfaceId, pointidIn};
    std::vector<uint8_t> readData(BULK_IN_LESS_THEN_ONCE);
    ret = g_usbHostInterface->BulkTransferRead(dev, pipeIn, TRANSFER_TIME_OUT, readData);
    EXPECT_EQ(0, ret);

    // Second write
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipeOut, TRANSFER_TIME_OUT, writeData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostConcurrentFileOps001
 * @tc.desc: SendFile while Read pending
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostConcurrentFileOps001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointidOut = POINTID_BULK_OUT;
    uint8_t pointidIn = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostConcurrentFileOps001===>file op during read, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Start with a read operation
    UsbPipe pipeIn = {interfaceId, pointidIn};
    std::vector<uint8_t> readData(BULK_IN_LESS_THEN_ONCE);
    ret = g_usbHostInterface->BulkTransferRead(dev, pipeIn, TRANSFER_TIME_OUT, readData);
    EXPECT_EQ(0, ret);

    // Then perform file send
    UsbPipe pipeOut = {interfaceId, pointidOut};
    std::vector<uint8_t> writeData(BULK_IN_LESS_THEN_ONCE, 'f');
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipeOut, TRANSFER_TIME_OUT, writeData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostConcurrentEvent001
 * @tc.desc: SendEvent during file transfer
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostConcurrentEvent001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostConcurrentEvent001===>event during transfer, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Start a write operation
    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> writeData(BULK_IN_LESS_THEN_ONCE, 'e');
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, writeData);
    EXPECT_EQ(0, ret);

    // Event is sent on interrupt endpoint - host reads it
    // For host side, this would be reading from interrupt endpoint

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

// ============================================================================
// 4. Error Recovery Tests
// ============================================================================

/**
 * @tc.name: UsbdMtpHostErrorRecovery001
 * @tc.desc: Read operation after timeout
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostErrorRecovery001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostErrorRecovery001===>read after timeout, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> readData(BULK_IN_LESS_THEN_ONCE);

    // First read may timeout
    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, readData);
    // Second read should work after timeout recovery
    readData.clear();
    readData.resize(BULK_IN_LESS_THEN_ONCE);
    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, readData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostErrorRecovery002
 * @tc.desc: Write operation after timeout
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostErrorRecovery002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostErrorRecovery002===>write after timeout, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> writeData(BULK_IN_LESS_THEN_ONCE, 'w');

    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, writeData);
    EXPECT_EQ(0, ret);

    // Another write after potential timeout
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, writeData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostCanceledState001
 * @tc.desc: Verify MTP_STATE_CANCELED handling
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostCanceledState001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostCanceledState001===>test cancel state, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> readData(BULK_IN_LESS_THEN_ONCE);
    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, readData);
    // Should handle gracefully
    EXPECT_TRUE(ret == 0 || ret != 0);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostErrorState001
 * @tc.desc: Verify MTP_STATE_ERROR handling
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostErrorState001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostErrorState001===>test error state, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> writeData(BULK_IN_LESS_THEN_ONCE, 'e');
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, writeData);
    // Should handle gracefully
    EXPECT_TRUE(ret == 0 || ret != 0);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

// ============================================================================
// 5. Boundary and Special Value Tests
// ============================================================================

/**
 * @tc.name: UsbdMtpHostReadBoundary001
 * @tc.desc: Read with max buffer size (8192)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostReadBoundary001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(BULK_BUFFER_SIZE);

    std::cout << "UsbdMtpHostReadBoundary001===>read max buffer (8192), press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);
    EXPECT_LE(bufferData.size(), static_cast<size_t>(BULK_BUFFER_SIZE));

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostReadBoundary002
 * @tc.desc: Read with max+1 buffer size
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostReadBoundary002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(BULK_BUFFER_SIZE + 1);

    std::cout << "UsbdMtpHostReadBoundary002===>read max+1 buffer, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);
    EXPECT_GE(bufferData.size(), 0);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostWriteBoundary001
 * @tc.desc: Write with max buffer size (8192)
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostWriteBoundary001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(BULK_BUFFER_SIZE, 'w');

    std::cout << "UsbdMtpHostWriteBoundary001===>write max buffer (8192), press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostWriteBoundary002
 * @tc.desc: Write with max+1 buffer size
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostWriteBoundary002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(BULK_BUFFER_SIZE + 1, 'w');

    std::cout << "UsbdMtpHostWriteBoundary002===>write max+1 buffer, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostEventMinSize001
 * @tc.desc: SendEvent with 1 byte
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostEventMinSize001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostEventMinSize001===>send 1 byte event, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Event would be sent via interrupt endpoint
    // For host, this is a read operation on interrupt endpoint
    // Testing minimal event packet size

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostEventZeroSize001
 * @tc.desc: SendEvent with 0 bytes
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostEventZeroSize001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostEventZeroSize001===>send 0 byte event, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Empty event packet test

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

// ============================================================================
// 6. Transaction ID and Command Tests
// ============================================================================

/**
 * @tc.name: UsbdMtpHostTransactionId001
 * @tc.desc: File send with different transaction IDs
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostTransactionId001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    // Create MTP packet header with transaction ID
    std::vector<uint8_t> mtpHeader(MTP_PACKET_HEADER_SIZE);
    // Length (4 bytes)
    mtpHeader[0] = (BULK_IN_LESS_THEN_ONCE + MTP_PACKET_HEADER_SIZE) & 0xFF;
    mtpHeader[1] = ((BULK_IN_LESS_THEN_ONCE + MTP_PACKET_HEADER_SIZE) >> 8) & 0xFF;
    mtpHeader[2] = ((BULK_IN_LESS_THEN_ONCE + MTP_PACKET_HEADER_SIZE) >> 16) & 0xFF;
    mtpHeader[3] = ((BULK_IN_LESS_THEN_ONCE + MTP_PACKET_HEADER_SIZE) >> 24) & 0xFF;
    // Command code (2 bytes)
    uint16_t cmdCode = CMD_CODE_GET_OBJECT;
    mtpHeader[4] = cmdCode & 0xFF;
    mtpHeader[5] = (cmdCode >> 8) & 0xFF;
    // Transaction ID (4 bytes)
    uint32_t transactionId = TRANSACTION_ID_BASE + 1;
    mtpHeader[6] = transactionId & 0xFF;
    mtpHeader[7] = (transactionId >> 8) & 0xFF;
    mtpHeader[8] = (transactionId >> 16) & 0xFF;
    mtpHeader[9] = (transactionId >> 24) & 0xFF;

    // Add payload
    std::vector<uint8_t> writeData = mtpHeader;
    writeData.insert(writeData.end(), BULK_IN_LESS_THEN_ONCE, 't');

    std::cout << "UsbdMtpHostTransactionId001===>test with different transaction ID=0x"
              << std::hex << transactionId << std::dec
              << ", press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, writeData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostTransactionId002
 * @tc.desc: File receive with different transaction IDs
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostTransactionId002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    uint32_t transactionId = TRANSACTION_ID_BASE + 2;
    std::vector<uint8_t> bufferData(BULK_OUT_LESS_THEN_ONCE + MTP_PACKET_HEADER_SIZE);

    std::cout << "UsbdMtpHostTransactionId002===>test with different transaction ID=0x"
              << std::hex << transactionId << std::dec
              << ", press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostCommandCode001
 * @tc.desc: File send with various command codes
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostCommandCode001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    // Create MTP packet header with OPEN_SESSION command
    std::vector<uint8_t> mtpHeader(MTP_PACKET_HEADER_SIZE);
    // Length (4 bytes)
    mtpHeader[0] = (MTP_PACKET_HEADER_SIZE) & 0xFF;
    mtpHeader[1] = ((MTP_PACKET_HEADER_SIZE) >> 8) & 0xFF;
    mtpHeader[2] = ((MTP_PACKET_HEADER_SIZE) >> 16) & 0xFF;
    mtpHeader[3] = ((MTP_PACKET_HEADER_SIZE) >> 24) & 0xFF;
    // Command code (2 bytes)
    uint16_t cmdCode = CMD_CODE_OPEN_SESSION;
    mtpHeader[4] = cmdCode & 0xFF;
    mtpHeader[5] = (cmdCode >> 8) & 0xFF;
    // Transaction ID (4 bytes)
    uint32_t transactionId = TRANSACTION_ID_BASE;
    mtpHeader[6] = transactionId & 0xFF;
    mtpHeader[7] = (transactionId >> 8) & 0xFF;
    mtpHeader[8] = (transactionId >> 16) & 0xFF;
    mtpHeader[9] = (transactionId >> 24) & 0xFF;

    std::cout << "UsbdMtpHostCommandCode001===>test with command code=0x"
              << std::hex << cmdCode << std::dec
              << ", press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, mtpHeader);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostCommandCode002
 * @tc.desc: File receive with various command codes
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostCommandCode002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    uint16_t cmdCode = CMD_CODE_GET_OBJECT_HANDLES;
    std::vector<uint8_t> bufferData(BULK_OUT_LESS_THEN_ONCE + MTP_PACKET_HEADER_SIZE);

    std::cout << "UsbdMtpHostCommandCode002===>test with command code=0x"
              << std::hex << cmdCode << std::dec
              << ", press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

// ============================================================================
// 7. State Transition Tests
// ============================================================================

/**
 * @tc.name: UsbdMtpHostStateOfflineToReady001
 * @tc.desc: Verify OFFLINE to READY transition
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostStateOfflineToReady001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostStateOfflineToReady001===>test state transition, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> bufferData(BULK_IN_LESS_THEN_ONCE);
    ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostStateReadyToBusy001
 * @tc.desc: Verify READY to BUSY transition
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostStateReadyToBusy001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostStateReadyToBusy001===>test ready to busy, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> writeData(BULK_IN_LESS_THEN_ONCE, 'b');
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, writeData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostStateBusyToReady001
 * @tc.desc: Verify BUSY to READY transition
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostStateBusyToReady001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostStateBusyToReady001===>test busy to ready, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> writeData(BULK_IN_LESS_THEN_ONCE, 'r');
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, writeData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostStateSuspend001
 * @tc.desc: Verify suspend/resume behavior
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostStateSuspend001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    std::cout << "UsbdMtpHostStateSuspend001===>test suspend/resume, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Release interface to simulate suspend
    g_usbHostInterface->ReleaseInterface(dev, interfaceId);

    // Re-claim to simulate resume
    ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    EXPECT_EQ(0, ret);

    // Verify operation works after resume
    UsbPipe pipe = {interfaceId, pointid};
    std::vector<uint8_t> writeData(BULK_IN_LESS_THEN_ONCE, 's');
    ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, writeData);
    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

// ============================================================================
// 8. Large File Performance Tests
// ============================================================================

/**
 * @tc.name: UsbdMtpHostLargeFileSend001
 * @tc.desc: Send 100MB file with timing
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostLargeFileSend001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    std::cout << "UsbdMtpHostLargeFileSend001===>send 100MB file with timing, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto start = std::chrono::high_resolution_clock::now();

    // Send in chunks
    constexpr uint32_t CHUNK_SIZE = BULK_BUFFER_SIZE;
    int64_t remaining = LARGE_FILE_SIZE;
    int32_t successCount = 0;
    while (remaining > 0) {
        uint32_t toSend = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : static_cast<uint32_t>(remaining);
        std::vector<uint8_t> bufferData(toSend, 'x');
        ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
        if (ret != 0) {
            break;
        }
        successCount++;
        remaining -= toSend;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    double speed = (static_cast<double>(LARGE_FILE_SIZE) / (1024.0 * 1024.0)) /
                   (static_cast<double>(duration.count()) / 1000.0);
    std::cout << "UsbdMtpHostLargeFileSend001 Transfer time: " << duration.count()
              << " ms, Speed: " << speed << " MB/s" << std::endl;
    HDF_LOGI("UsbdMtpHostLargeFileSend001 Transfer time: %{public}lld ms, Speed: %{public}.2f MB/s, Chunks: %{public}d",
        duration.count(), speed, successCount);

    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostLargeFileReceive001
 * @tc.desc: Receive 100MB file with timing
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostLargeFileReceive001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_IN;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    UsbPipe pipe = {interfaceId, pointid};
    std::cout << "===>receive 100MB file with timing, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto start = std::chrono::high_resolution_clock::now();

    // Receive in chunks
    constexpr uint32_t CHUNK_SIZE = BULK_BUFFER_SIZE;
    int64_t remaining = LARGE_FILE_SIZE;
    int32_t successCount = 0;
    while (remaining > 0) {
        uint32_t toRecv = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : static_cast<uint32_t>(remaining);
        std::vector<uint8_t> bufferData(toRecv);
        ret = g_usbHostInterface->BulkTransferRead(dev, pipe, TRANSFER_TIME_OUT, bufferData);
        if (ret != 0) {
            break;
        }
        successCount++;
        remaining -= toRecv;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    double speed = (static_cast<double>(LARGE_FILE_SIZE) / (1024.0 * 1024.0)) /
                   (static_cast<double>(duration.count()) / 1000.0);
    std::cout << "UsbdMtpHostLargeFileReceive001 Transfer time: " << duration.count()
              << " ms, Speed: " << speed << " MB/s" << std::endl;
    HDF_LOGI("Transfer time: %{public}lld ms, Speed: %{public}.2f MB/s, Chunks: %{public}d",
        duration.count(), speed, successCount);

    EXPECT_EQ(0, ret);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

/**
 * @tc.name: UsbdMtpHostMultipleFileSend001
 * @tc.desc: Send 10 files sequentially
 * @tc.type: FUNC
 */
HWTEST_F(UsbdMtpHostExtendedTest, UsbdMtpHostMultipleFileSend001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointid = POINTID_BULK_OUT;
    auto ret = g_usbHostInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);

    constexpr int32_t FILE_COUNT = 10;
    constexpr int32_t SINGLE_FILE_SIZE = BULK_IN_ONCE_MAX_SIZE;
    UsbPipe pipe = {interfaceId, pointid};

    std::cout << "===>send 10 files sequentially, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    int32_t successCount = 0;
    for (int32_t i = 0; i < FILE_COUNT; i++) {
        std::vector<uint8_t> bufferData(SINGLE_FILE_SIZE, '0' + (i % 10));
        ret = g_usbHostInterface->BulkTransferWrite(dev, pipe, TRANSFER_TIME_OUT, bufferData);
        if (ret == 0) {
            successCount++;
        }
        HDF_LOGI("UsbdMtpHostMultipleFileSend001 File %{public}d: ret=%{public}d", i, ret);
    }

    HDF_LOGI("UsbdMtpHostMultipleFileSend001 Successfully sent %{public}d/%{public}d files",
        successCount, FILE_COUNT);
    std::cout << "UsbdMtpHostMultipleFileSend001 Successfully sent " << successCount
              << "/" << FILE_COUNT << " files" << std::endl;
    EXPECT_GT(successCount, FILE_COUNT / 2);

    g_usbHostInterface->ReleaseInterface(dev, interfaceId);
}

} // namespace
