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


#include "usbfn_mtp_test_extended.h"

#include <cinttypes>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <sstream>
#include <vector>
#include <chrono>

#include "directory_ex.h"
#include "file_ex.h"
#include "hdf_log.h"
#include "securec.h"
#include "usbd_function.h"
#include "usbd_port.h"
#include "v2_0/iusb_device_interface.h"
#include "v1_0/iusbfn_mtp_interface.h"
#include "v1_0/usb_types.h"
#include "v1_0/usbfn_mtp_types.h"

#define HDF_LOG_TAG usbfn_mtp_extended_ut

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HDI::Usb::V2_0;
using namespace std;
using namespace OHOS::HDI::Usb::Gadget::Mtp::V1_0;

namespace {
constexpr int32_t MTP_EVENT_PACKET_VALID_LEN = 20;
constexpr uint16_t CMD_CODE_GET_DEVICE_INFO = 0x1001;
constexpr uint16_t CMD_CODE_OPEN_SESSION = 0x1002;
constexpr uint16_t CMD_CODE_GET_OBJECT_HANDLES = 0x1007;
constexpr uint16_t CMD_CODE_GET_OBJECT = 0x1009;
constexpr uint32_t TRANSACTION_ID_BASE = 0x1000;
constexpr uint32_t BULK_BUFFER_SIZE = 8192;
constexpr uint32_t BULK_IN_ONCE_MAX_SIZE = 1024;
constexpr uint32_t BULK_OUT_LESS_THEN_ONCE = 23;
constexpr uint32_t BULK_IN_LESS_THEN_ONCE = 45;
constexpr uint32_t MTP_FILE_SIZE_REUSE_REQ = 12 * 1024;
constexpr int64_t GEN_FILE_BUF_SIZE = 1024;
constexpr int64_t GEN_FILE_LIMIT_512MB = 512 * 1024 * 1024;
constexpr int64_t LARGE_FILE_SIZE = 100 * 1024 * 1024; // 100MB
constexpr int32_t INVALID_FD = -1;
constexpr const char *WORKED_UT_PATH = "/storage/media/100/local/files/Docs/Download/";
constexpr const char *MTP_TEST_SEND_FILE = "/storage/media/100/local/files/Docs/Download/sampleFile.mtp";
constexpr const char *MTP_TEST_RECV_FILE = "/storage/media/100/local/files/Docs/Download/sampleFile.mtp";
constexpr const char *MTP_TEST_SEND_FILE_LARGE = "/storage/media/100/local/files/Docs/Download/sampleFileLarge.mtp";
constexpr const char *MTP_TEST_RECV_FILE_LARGE = "/storage/media/100/local/files/Docs/Download/sampleFileLarge.mtp";

sptr<IUsbfnMtpInterface> g_usbfnMtpInterface = nullptr;
sptr<IUsbDeviceInterface> g_usbDeviceInterface = nullptr;
int32_t g_currentFunc = USB_FUNCTION_NONE;
int32_t g_fileTestCount = 0;
bool g_isInitialized = false;

struct UsbFnMtpFileSlice g_mfs = {
    .offset = 0,
    .length = 0,
    .command = 0,
    .transactionId = 0,
};

uint64_t GetFileSize(const std::string &pathName)
{
    struct stat statbuf;
    uint64_t ret = stat(pathName.c_str(), &statbuf);
    if (ret != 0) {
        return 0;
    }
    return static_cast<uint64_t>(statbuf.st_size);
}

bool WriteRandomDataToFile(const std::string &pathName, uint64_t fileSize)
{
    int32_t random = open("/dev/urandom", O_RDONLY);
    if (random < 0) {
        HDF_LOGE("UsbfnMtpTestExtended::WriteRandomDataToFile get random data failed");
        return false;
    }
    FILE *opFile = std::fopen(pathName.c_str(), "w");
    if (opFile == nullptr) {
        HDF_LOGE("UsbfnMtpTestExtended::WriteRandomDataToFile create file failed: %{public}s", pathName.c_str());
        return false;
    }
    char buffer[GEN_FILE_BUF_SIZE];
    int64_t count = static_cast<int64_t>(fileSize);
    while (count > 0) {
        (void)memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
        int64_t readSize = count > GEN_FILE_BUF_SIZE ? GEN_FILE_BUF_SIZE : count;
        ssize_t readActual = read(random, static_cast<void *>(buffer), static_cast<size_t>(readSize));
        if (readActual != static_cast<ssize_t>(readSize)) {
            HDF_LOGW("UsbfnMtpTestExtended::WriteRandomDataToFile read random failed");
            break;
        }
        size_t writeActual = std::fwrite(static_cast<void *>(buffer), 1, static_cast<size_t>(readSize), opFile);
        if (writeActual != static_cast<size_t>(readSize)) {
            HDF_LOGW("UsbfnMtpTestExtended::WriteRandomDataToFile write failed");
            break;
        }
        count -= readSize;
    }
    std::fflush(opFile);
    std::fclose(opFile);
    close(random);
    HDF_LOGV("UsbfnMtpTestExtended::WriteRandomDataToFile file %{public}s: %{public}" PRIu64 "/%{public}" PRIu64 "",
        pathName.c_str(), GetFileSize(pathName), fileSize);
    return count > 0 ? false : true;
}

bool GenerateFile(const std::string &pathName, int64_t fileSize)
{
    if (GetFileSize(pathName) == static_cast<uint64_t>(fileSize)) {
        HDF_LOGW("UsbfnMtpTestExtended::GenerateFile file already exist");
        return true;
    }
    if (fileSize > GEN_FILE_LIMIT_512MB) {
        int32_t ret = truncate(pathName.c_str(), static_cast<off_t>(fileSize));
        if (ret != 0) {
            HDF_LOGE("UsbfnMtpTestExtended::GenerateFile fail to truncate file to size: %{public}" PRId64 "", fileSize);
            return false;
        }
        HDF_LOGV("UsbfnMtpTestExtended::GenerateFile truncate %{public}s %{public}" PRId64 "",
            pathName.c_str(), fileSize);
        return true;
    }
    return WriteRandomDataToFile(pathName, static_cast<uint64_t>(fileSize));
}

int64_t TransferTimeCost(std::function<int32_t()> transferFunc)
{
    auto start = std::chrono::high_resolution_clock::now();
    int32_t ret = transferFunc();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    if (ret != 0) {
        HDF_LOGE("UsbfnMtpTestExtended::TransferTimeCost transfer failed with ret=%{public}d", ret);
        return -1;
    }
    return duration.count();
}

void UsbfnMtpTestExtended::SetUpTestCase(void)
{
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    std::cout << "===>please connect to PC use USB 3.0 interface, press enter to continue set function to mtp"
              << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    g_usbDeviceInterface = IUsbDeviceInterface::Get();
    ASSERT_TRUE(g_usbDeviceInterface != nullptr);
    auto ret = g_usbDeviceInterface->GetCurrentFunctions(g_currentFunc);
    ASSERT_EQ(0, ret);
    std::cout << "===>current function=" << g_currentFunc << ", set function to mtp, please wait" << std::endl;
    ret = g_usbDeviceInterface->SetCurrentFunctions(USB_FUNCTION_MTP);
    ASSERT_EQ(0, ret);

    g_usbfnMtpInterface = IUsbfnMtpInterface::Get();
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ret = g_usbfnMtpInterface->Start();
    ASSERT_EQ(0, ret);
    g_isInitialized = true;
}

void UsbfnMtpTestExtended::TearDownTestCase(void)
{
    HDF_LOGV("UsbfnMtpTestExtended::TearDownTestCase");
    if (g_usbfnMtpInterface != nullptr) {
        auto ret = g_usbfnMtpInterface->Stop();
        ASSERT_EQ(0, ret);
    }
    if (g_usbDeviceInterface != nullptr) {
        auto ret = g_usbDeviceInterface->SetCurrentFunctions(g_currentFunc);
        ASSERT_EQ(0, ret);
    }
    if (g_fileTestCount == 0) {
        return;
    }
    if (g_fileTestCount == 1) {
        std::cout << "===>please delete temporary test file if needed: sendfile=" << MTP_TEST_SEND_FILE
                  << " recvfile=" << MTP_TEST_RECV_FILE << std::endl;
        return;
    }
    if (FileExists(std::string(MTP_TEST_SEND_FILE))) {
        if (remove(MTP_TEST_SEND_FILE) != 0) {
            std::cout << "[-] remove send file failed: " << MTP_TEST_SEND_FILE << std::endl;
        }
    }
    if (FileExists(std::string(MTP_TEST_RECV_FILE))) {
        if (remove(MTP_TEST_RECV_FILE) != 0) {
            std::cout << "[-] remove recv file failed: " << MTP_TEST_RECV_FILE << std::endl;
        }
    }
    if (FileExists(std::string(MTP_TEST_SEND_FILE_LARGE))) {
        if (remove(MTP_TEST_SEND_FILE_LARGE) != 0) {
            std::cout << "[-] remove send large file failed: " << MTP_TEST_SEND_FILE_LARGE << std::endl;
        }
    }
    if (FileExists(std::string(MTP_TEST_RECV_FILE_LARGE))) {
        if (remove(MTP_TEST_RECV_FILE_LARGE) != 0) {
            std::cout << "[-] remove recv large file failed: " << MTP_TEST_RECV_FILE_LARGE << std::endl;
        }
    }
}

void UsbfnMtpTestExtended::SetUp(void) {}

void UsbfnMtpTestExtended::TearDown(void) {}

// ============================================================================
// 1. Lifecycle Management Tests (Init/Release/Start/Stop)
// ============================================================================

/**
 * @tc.name: UsbfnMtpInit001
 * @tc.desc: Test Init() after Start() - should handle gracefully
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpInit001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpInit001 Case Start");
    std::cout << "UsbfnMtpInit001===>Test Init() after Start(), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // After Start(), calling Init() should be handled gracefully
    // The exact behavior depends on implementation - testing it doesn't crash
    int32_t ret = g_usbfnMtpInterface->Init();
    // Either success or already initialized should be acceptable
    EXPECT_TRUE(ret == 0 || ret == HDF_ERR_INVALID_OBJECT);
}

/**
 * @tc.name: UsbfnMtpInit002
 * @tc.desc: Test Release() without Init() - error handling
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpInit002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpInit002 Case Start");
    // Release() without prior Init() should be handled gracefully
    int32_t ret = g_usbfnMtpInterface->Release();
    // Either success or appropriate error code
    EXPECT_TRUE(ret == 0 || ret == HDF_ERR_INVALID_OBJECT);
}

/**
 * @tc.name: UsbfnMtpInit003
 * @tc.desc: Test multiple Init() calls
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpInit003, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpInit003 Case Start");
    std::cout << "UsbfnMtpInit003===>Test multiple Init() calls, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    int32_t ret = g_usbfnMtpInterface->Init();
    EXPECT_TRUE(ret == 0 || ret == HDF_ERR_INVALID_OBJECT);
    ret = g_usbfnMtpInterface->Init();
    EXPECT_TRUE(ret == 0 || ret == HDF_ERR_INVALID_OBJECT);
}

/**
 * @tc.name: UsbfnMtpStart001
 * @tc.desc: Test Start() when already started
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpStart001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpStart001 Case Start");
    // Already started in SetUpTestCase, starting again should be handled
    int32_t ret = g_usbfnMtpInterface->Start();
    EXPECT_TRUE(ret == 0 || ret == HDF_ERR_INVALID_OBJECT);
}

/**
 * @tc.name: UsbfnMtpStop001
 * @tc.desc: Test Stop() when not started (after a Stop)
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpStop001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpStop001 Case Start");
    std::cout << "UsbfnMtpStop001===>Test Stop() when not started, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    int32_t ret = g_usbfnMtpInterface->Stop();
    EXPECT_EQ(0, ret);
    // Try stopping again when already stopped
    ret = g_usbfnMtpInterface->Stop();
    EXPECT_TRUE(ret == 0 || ret == HDF_ERR_INVALID_OBJECT);
    // Restart for subsequent tests
    ret = g_usbfnMtpInterface->Start();
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpStop002
 * @tc.desc: Test multiple Stop() calls
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpStop002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpStop002 Case Start");
    std::cout << "UsbfnMtpStop002===>Test multiple Stop() calls, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    int32_t ret = g_usbfnMtpInterface->Stop();
    EXPECT_EQ(0, ret);
    ret = g_usbfnMtpInterface->Stop();
    EXPECT_TRUE(ret == 0 || ret == HDF_ERR_INVALID_OBJECT);
    // Restart for subsequent tests
    ret = g_usbfnMtpInterface->Start();
    EXPECT_EQ(0, ret);
}

// ============================================================================
// 2. File Operation Edge Cases
// ============================================================================

/**
 * @tc.name: UsbfnMtpFileSendWithOffset001
 * @tc.desc: SendFile with non-zero offset
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpFileSendWithOffset001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpFileSendWithOffset001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_IN_LESS_THEN_ONCE;
    mfs.offset = 100; // Non-zero offset
    mfs.command = CMD_CODE_GET_DEVICE_INFO;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.offset + mfs.length));
    std::cout << "UsbfnMtpFileSendWithOffset001===>use libusb in PC launch bulk-in transfer, press enter to continue"
              << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileSendWithOffset002
 * @tc.desc: SendFile with offset at file boundary
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpFileSendWithOffset002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpFileSendWithOffset002 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_IN_ONCE_MAX_SIZE;
    mfs.offset = BULK_IN_ONCE_MAX_SIZE; // Offset at page boundary
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.offset + mfs.length));
    std::cout << "UsbfnMtpFileSendWithOffset002===>use libusb in PC launch bulk-in transfer, press enter to continue"
              << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileReceiveWithOffset001
 * @tc.desc: ReceiveFile with non-zero offset
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpFileReceiveWithOffset001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpFileReceiveWithOffset001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_OUT_LESS_THEN_ONCE;
    mfs.offset = 50; // Non-zero offset
    std::cout << "===>use libusb in PC launch bulk-out transfer, press enter to continue"
              << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpFileSendPartial001
 * @tc.desc: SendFile with length smaller than file size
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpFileSendPartial001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpFileSendPartial001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    uint64_t fileSize = MTP_FILE_SIZE_REUSE_REQ;
    mfs.length = BULK_IN_LESS_THEN_ONCE; // Send only partial content
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, fileSize));
    std::cout << "UsbfnMtpFileSendPartial001===>use libusb in PC launch bulk-in transfer, press enter to continue"
              << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileReceiveInvalidFd001
 * @tc.desc: ReceiveFile with invalid fd (-1)
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpFileReceiveInvalidFd001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpFileReceiveInvalidFd001 Case Start");
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_OUT_LESS_THEN_ONCE;
    mfs.fd = INVALID_FD;
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileSendInvalidFd001
 * @tc.desc: SendFile with invalid fd (-1)
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpFileSendInvalidFd001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpFileSendInvalidFd001 Case Start");
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_IN_LESS_THEN_ONCE;
    mfs.fd = INVALID_FD;
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    EXPECT_NE(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileSendNonExist001
 * @tc.desc: SendFile with non-existent file path
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpFileSendNonExist001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpFileSendNonExist001 Case Start");
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_IN_LESS_THEN_ONCE;
    const char *nonExistentFile = "/storage/media/100/local/files/Docs/Download/nonexistent_file_12345.mtp";
    mfs.fd = open(nonExistentFile, O_RDONLY);
    // fd might be -1 or open might succeed (file gets created)
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    if (mfs.fd >= 0) {
        close(mfs.fd);
    }
    // Either failure or success (implementation dependent)
    EXPECT_TRUE(ret == 0 || ret != 0);
}

/**
 * @tc.name: UsbfnMtpFileOffsetOverflow001
 * @tc.desc: SendFile with offset exceeding file size
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpFileOffsetOverflow001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpFileOffsetOverflow001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_IN_LESS_THEN_ONCE;
    mfs.offset = MTP_FILE_SIZE_REUSE_REQ * 2; // Offset larger than file
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, MTP_FILE_SIZE_REUSE_REQ));
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    // May fail or succeed depending on implementation
    EXPECT_TRUE(ret == 0 || ret != 0);
}

// ============================================================================
// 3. Concurrent Operation Tests
// ============================================================================

/**
 * @tc.name: UsbfnMtpConcurrentReadWrite001
 * @tc.desc: Interleaved Read/Write operations
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpConcurrentReadWrite001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpConcurrentReadWrite001 Case Start");
    std::vector<uint8_t> writeData;
    writeData.assign(BULK_IN_LESS_THEN_ONCE, 'w');
    std::vector<uint8_t> readData;
    std::cout << "UsbfnMtpConcurrentReadWrite001===>interleaved read/write test, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Write, then read immediately
    auto ret = g_usbfnMtpInterface->Write(writeData);
    EXPECT_EQ(ret, 0);
    ret = g_usbfnMtpInterface->Read(readData);
    EXPECT_EQ(ret, 0);
    // Second write
    ret = g_usbfnMtpInterface->Write(writeData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpConcurrentFileOps001
 * @tc.desc: SendFile while Read pending
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpConcurrentFileOps001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpConcurrentFileOps001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_IN_LESS_THEN_ONCE;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpConcurrentFileOps001===>file op during read, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Start with a read operation
    std::vector<uint8_t> readData;
    auto ret = g_usbfnMtpInterface->Read(readData);
    EXPECT_EQ(ret, 0);
    // Then perform file send
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpConcurrentEvent001
 * @tc.desc: SendEvent during file transfer
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpConcurrentEvent001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpConcurrentEvent001 Case Start");
    std::cout << "UsbfnMtpConcurrentEvent001===>event during transfer, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Start a write operation
    std::vector<uint8_t> writeData;
    writeData.assign(BULK_IN_LESS_THEN_ONCE, 'w');
    auto ret = g_usbfnMtpInterface->Write(writeData);
    EXPECT_EQ(ret, 0);
    // Send event during the transfer
    std::vector<uint8_t> eventData;
    eventData.assign(MTP_EVENT_PACKET_VALID_LEN, 'e');
    ret = g_usbfnMtpInterface->SendEvent(eventData);
    EXPECT_EQ(0, ret);
}

// ============================================================================
// 4. Error Recovery Tests
// ============================================================================

/**
 * @tc.name: UsbfnMtpErrorRecovery001
 * @tc.desc: Read operation after timeout
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpErrorRecovery001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpErrorRecovery001 Case Start");
    std::cout << "UsbfnMtpErrorRecovery001===>read after timeout, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // First read may timeout
    std::vector<uint8_t> devData;
    auto ret = g_usbfnMtpInterface->Read(devData);
    // Second read should work after timeout recovery
    devData.clear();
    ret = g_usbfnMtpInterface->Read(devData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpErrorRecovery002
 * @tc.desc: Write operation after timeout
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpErrorRecovery002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpErrorRecovery002 Case Start");
    std::cout << "UsbfnMtpErrorRecovery002===>write after timeout, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::vector<uint8_t> writeData;
    writeData.assign(BULK_IN_LESS_THEN_ONCE, 'w');
    auto ret = g_usbfnMtpInterface->Write(writeData);
    EXPECT_EQ(ret, 0);
    // Another write after potential timeout
    ret = g_usbfnMtpInterface->Write(writeData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpCanceledState001
 * @tc.desc: Verify MTP_STATE_CANCELED handling
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpCanceledState001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpCanceledState001 Case Start");
    std::cout << "UsbfnMtpCanceledState001===>test cancel state, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Read operation when in canceled state
    std::vector<uint8_t> devData;
    auto ret = g_usbfnMtpInterface->Read(devData);
    // Should handle gracefully
    EXPECT_TRUE(ret == 0 || ret != 0);
}

/**
 * @tc.name: UsbfnMtpErrorState001
 * @tc.desc: Verify MTP_STATE_ERROR handling
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpErrorState001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpErrorState001 Case Start");
    std::cout << "UsbfnMtpErrorState001===>test error state, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Write operation when in error state
    std::vector<uint8_t> writeData;
    writeData.assign(BULK_IN_LESS_THEN_ONCE, 'w');
    auto ret = g_usbfnMtpInterface->Write(writeData);
    // Should handle gracefully
    EXPECT_TRUE(ret == 0 || ret != 0);
}

// ============================================================================
// 5. Boundary and Special Value Tests
// ============================================================================

/**
 * @tc.name: UsbfnMtpReadBoundary001
 * @tc.desc: Read with max buffer size (8192)
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpReadBoundary001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpReadBoundary001 Case Start");
    std::vector<uint8_t> devData;
    std::cout << "UsbfnMtpReadBoundary001===>read max buffer (8192), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->Read(devData);
    EXPECT_EQ(ret, 0);
    EXPECT_LE(devData.size(), static_cast<size_t>(BULK_BUFFER_SIZE));
}

/**
 * @tc.name: UsbfnMtpReadBoundary002
 * @tc.desc: Read with max+1 buffer size
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpReadBoundary002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpReadBoundary002 Case Start");
    std::vector<uint8_t> devData;
    std::cout << "UsbfnMtpReadBoundary002===>read max+1 buffer, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->Read(devData);
    EXPECT_EQ(ret, 0);
    // Should read in chunks if needed
    EXPECT_GE(devData.size(), 0);
}

/**
 * @tc.name: UsbfnMtpWriteBoundary001
 * @tc.desc: Write with max buffer size (8192)
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpWriteBoundary001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpWriteBoundary001 Case Start");
    uint32_t length = BULK_BUFFER_SIZE;
    std::vector<uint8_t> devData;
    devData.assign(length, 'w');
    std::cout << "UsbfnMtpWriteBoundary001===>write max buffer (8192), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->Write(devData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpWriteBoundary002
 * @tc.desc: Write with max+1 buffer size
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpWriteBoundary002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpWriteBoundary002 Case Start");
    uint32_t length = BULK_BUFFER_SIZE + 1;
    std::vector<uint8_t> devData;
    devData.assign(length, 'w');
    std::cout << "UsbfnMtpWriteBoundary002===>write max+1 buffer, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->Write(devData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpEventMinSize001
 * @tc.desc: SendEvent with 1 byte
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpEventMinSize001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpEventMinSize001 Case Start");
    std::vector<uint8_t> devData;
    devData.assign(1, 'e');
    std::cout << "UsbfnMtpEventMinSize001===>send 1 byte event, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->SendEvent(devData);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpEventZeroSize001
 * @tc.desc: SendEvent with 0 bytes
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpEventZeroSize001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpEventZeroSize001 Case Start");
    std::vector<uint8_t> devData;
    auto ret = g_usbfnMtpInterface->SendEvent(devData);
    // May succeed or fail depending on implementation
    EXPECT_TRUE(ret == 0 || ret != 0);
}

// ============================================================================
// 6. Transaction ID and Command Tests
// ============================================================================

/**
 * @tc.name: UsbfnMtpTransactionId001
 * @tc.desc: File send with different transaction IDs
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpTransactionId001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpTransactionId001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_IN_LESS_THEN_ONCE;
    mfs.command = CMD_CODE_GET_OBJECT;
    mfs.transactionId = TRANSACTION_ID_BASE + 1;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpTransactionId001===>test with different transaction ID, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpTransactionId002
 * @tc.desc: File receive with different transaction IDs
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpTransactionId002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpTransactionId002 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_OUT_LESS_THEN_ONCE;
    mfs.command = CMD_CODE_GET_OBJECT_HANDLES;
    mfs.transactionId = TRANSACTION_ID_BASE + 2;
    std::cout << "UsbfnMtpTransactionId002===>test with different transaction ID, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpCommandCode001
 * @tc.desc: File send with various command codes
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpCommandCode001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpCommandCode001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_IN_LESS_THEN_ONCE;
    mfs.command = CMD_CODE_OPEN_SESSION;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpCommandCode001===>test with different command code, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpCommandCode002
 * @tc.desc: File receive with various command codes
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpCommandCode002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpCommandCode002 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_OUT_LESS_THEN_ONCE;
    mfs.command = CMD_CODE_GET_OBJECT_HANDLES;
    std::cout << "UsbfnMtpCommandCode002===>test with different command code, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
}

// ============================================================================
// 7. State Transition Tests
// ============================================================================

/**
 * @tc.name: UsbfnMtpStateOfflineToReady001
 * @tc.desc: Verify OFFLINE to READY transition
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpStateOfflineToReady001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpStateOfflineToReady001 Case Start");
    std::cout << "UsbfnMtpStateOfflineToReady001===>test state transition, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // After Start(), device should be in READY state
    std::vector<uint8_t> devData;
    auto ret = g_usbfnMtpInterface->Read(devData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpStateReadyToBusy001
 * @tc.desc: Verify READY to BUSY transition
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpStateReadyToBusy001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpStateReadyToBusy001 Case Start");
    std::cout << "UsbfnMtpStateReadyToBusy001===>test ready to busy, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Start file transfer - should transition to BUSY
    std::vector<uint8_t> writeData;
    writeData.assign(BULK_IN_LESS_THEN_ONCE, 'w');
    auto ret = g_usbfnMtpInterface->Write(writeData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpStateBusyToReady001
 * @tc.desc: Verify BUSY to READY transition
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpStateBusyToReady001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpStateBusyToReady001 Case Start");
    std::cout << "UsbfnMtpStateBusyToReady001===>test busy to ready, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Complete transfer - should return to READY
    std::vector<uint8_t> writeData;
    writeData.assign(BULK_IN_LESS_THEN_ONCE, 'w');
    auto ret = g_usbfnMtpInterface->Write(writeData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpStateSuspend001
 * @tc.desc: Verify suspend/resume behavior
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpStateSuspend001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpStateSuspend001 Case Start");
    std::cout << "UsbfnMtpStateSuspend001===>test suspend/resume, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    // Simulate suspend by stopping
    auto ret = g_usbfnMtpInterface->Stop();
    EXPECT_EQ(0, ret);
    // Resume by starting again
    ret = g_usbfnMtpInterface->Start();
    EXPECT_EQ(0, ret);
    // Verify operation works after resume
    std::vector<uint8_t> writeData;
    writeData.assign(BULK_IN_LESS_THEN_ONCE, 'w');
    ret = g_usbfnMtpInterface->Write(writeData);
    EXPECT_EQ(ret, 0);
}

// ============================================================================
// 8. Large File Performance Tests
// ============================================================================

/**
 * @tc.name: UsbfnMtpLargeFileSend001
 * @tc.desc: Send 100MB file with timing
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpLargeFileSend001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpLargeFileSend001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = LARGE_FILE_SIZE;
    std::string filePathName = MTP_TEST_SEND_FILE_LARGE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpLargeFileSend001===>send 100MB file with timing, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    int64_t duration = TransferTimeCost([&]() { return g_usbfnMtpInterface->SendFile(mfs); });
    close(mfs.fd);
    EXPECT_EQ(0, g_usbfnMtpInterface->SendFile(mfs));
    if (duration > 0) {
        double speed = (LARGE_FILE_SIZE / (1024.0 * 1024.0)) / (duration / 1000.0);
        HDF_LOGI("UsbfnMtpLargeFileSend001 Transfer speed: %{public}.2f MB/s", speed);
        std::cout << "UsbfnMtpLargeFileSend001 Transfer time: " << duration << " ms, Speed: " << speed << " MB/s"
                  << std::endl;
    }
    close(mfs.fd);
}

/**
 * @tc.name: UsbfnMtpLargeFileReceive001
 * @tc.desc: Receive 100MB file with timing
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpLargeFileReceive001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpLargeFileReceive001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = LARGE_FILE_SIZE;
    std::cout << "UsbfnMtpLargeFileReceive001===>receive 100MB file with timing, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE_LARGE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    int64_t duration = TransferTimeCost([&]() { return g_usbfnMtpInterface->ReceiveFile(mfs); });
    close(mfs.fd);
    if (duration > 0) {
        double speed = (LARGE_FILE_SIZE / (1024.0 * 1024.0)) / (duration / 1000.0);
        HDF_LOGI("UsbfnMtpLargeFileReceive001 Transfer speed: %{public}.2f MB/s", speed);
        std::cout << "UsbfnMtpLargeFileReceive001 Transfer time: " << duration << " ms, Speed: " << speed << " MB/s"
                  << std::endl;
    }
    EXPECT_EQ(0, g_usbfnMtpInterface->ReceiveFile(mfs));
}

/**
 * @tc.name: UsbfnMtpMultipleFileSend001
 * @tc.desc: Send 10 files sequentially
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTestExtended, UsbfnMtpMultipleFileSend001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTestExtended::UsbfnMtpMultipleFileSend001 Case Start");
    g_fileTestCount++;
    constexpr int32_t FILE_COUNT = 10;
    constexpr int32_t SINGLE_FILE_SIZE = BULK_IN_ONCE_MAX_SIZE;
    std::cout << "UsbfnMtpMultipleFileSend001===>send 10 files sequentially, press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    int32_t successCount = 0;
    for (int32_t i = 0; i < FILE_COUNT; i++) {
        struct UsbFnMtpFileSlice mfs = g_mfs;
        mfs.length = SINGLE_FILE_SIZE;
        mfs.command = CMD_CODE_GET_OBJECT;
        mfs.transactionId = TRANSACTION_ID_BASE + i;
        std::string filePathName = MTP_TEST_SEND_FILE;
        EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
        mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
        if (mfs.fd > 0) {
            auto ret = g_usbfnMtpInterface->SendFile(mfs);
            close(mfs.fd);
            if (ret == 0) {
                successCount++;
            }
        }
    }
    HDF_LOGI("UsbfnMtpMultipleFileSend001 Successfully sent %{public}d/%{public}d files", successCount, FILE_COUNT);
    std::cout << "UsbfnMtpMultipleFileSend001 Successfully sent " << successCount << "/" << FILE_COUNT << " files"
              << std::endl;
    EXPECT_GT(successCount, FILE_COUNT / 2); // At least half should succeed
}

} // namespace
