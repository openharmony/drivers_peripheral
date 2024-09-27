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

#include "usbfn_mtp_test.h"

#include <cinttypes>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <vector>

#include "directory_ex.h"
#include "file_ex.h"
#include "hdf_log.h"
#include "securec.h"
#include "usbd_function.h"
#include "usbd_port.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/iusbfn_mtp_interface.h"
#include "v1_0/usb_types.h"
#include "v1_0/usbfn_mtp_types.h"

#define HDF_LOG_TAG usbfn_mtp_ut

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::HDI::Usb::V1_0;
using namespace std;
using namespace OHOS::HDI::Usb::Gadget::Mtp::V1_0;

namespace {
constexpr int32_t SLEEP_TIME = 3;
constexpr int32_t MTP_EVENT_PACKET_MAX_BYTES = 28;
constexpr int32_t MTP_EVENT_PACKET_VALID_LEN = 20;
constexpr int32_t MTP_EVENT_PACKET_INVALID_LEN = 29;
constexpr uint16_t CMD_CODE_GET_DEVICE_INFO = 0x1001;
constexpr uint32_t TRANSACTION_ID_RANDOM = 0xF00D;
/* mtp packet head defined as [struct UsbMtpDataHeader] in usbfn_mtp_impl.h  */
constexpr uint32_t MTP_PACKET_HEADER_SIZE = 12;
constexpr uint32_t BULK_OUT_ONCE_MAX_SIZE = 1024;
constexpr uint32_t BULK_OUT_LESS_THEN_ONCE = 23;
constexpr uint32_t BULK_OUT_MORE_THEN_ONCE = 1025;
constexpr uint32_t BULK_IN_ONCE_MAX_SIZE = 1024;
constexpr uint32_t BULK_IN_LESS_THEN_ONCE = 45;
constexpr uint32_t BULK_IN_MORE_THEN_ONCE = 2023;
constexpr uint32_t MTP_FILE_SIZE_ONE_REQ = 1024;
constexpr uint32_t MTP_FILE_SIZE_REUSE_REQ = 12 * 1024;
/* 0xFFFFFFFFLL is 4 * 1024 * 1024 * 1024 - 1 = 4GB - 1 */
constexpr int64_t MTP_MAX_FILE_SIZE = 0xFFFFFFFFLL;
constexpr int64_t GEN_FILE_BUF_SIZE = 1024;
constexpr int64_t GEN_FILE_LIMIT_512MB = 512 * 1024 * 1024;
constexpr int32_t PRINT_VECTOR_MAX_LENGTH = 30;
constexpr const char *WORKED_UT_PATH = "/data/local/tmp/";
constexpr const char *MTP_TEST_SEND_FILE = "/data/local/tmp/sampleFile.mtp";
constexpr const char *MTP_TEST_RECV_FILE = "/data/local/tmp/sampleFile.mtp";

sptr<IUsbfnMtpInterface> g_usbfnMtpInterface = nullptr;
sptr<IUsbInterface> g_usbInterface = nullptr;
int32_t g_currentFunc = USB_FUNCTION_NONE;
int32_t g_fileTestCount = 0;

struct UsbFnMtpFileSlice g_mfs = {
    .offset = 0,
    .length = 0,
    .command = 0,
    .transactionId = 0,
};

void PrintVector(const std::string &msg, std::vector<uint8_t> &data, bool hexFormat)
{
    size_t printLen = data.size();
    bool ignore = false;
    if (printLen > static_cast<size_t>(PRINT_VECTOR_MAX_LENGTH)) {
        printLen = static_cast<size_t>(PRINT_VECTOR_MAX_LENGTH);
        ignore = true;
    }
    std::stringstream ss;
    for (size_t i = 0; i < printLen; i++) {
        if (hexFormat) {
            ss << std::hex << "0x" << (0xFF & data.at(i)) << " ";
        } else {
            ss << data.at(i);
        }
    }
    std::string output = msg + std::string("(") + std::to_string(printLen) + std::string("):") + ss.str();
    if (ignore) {
        output += "......";
    }
    HDF_LOGV("UsbfnMtpTest::PrintVector %{public}s", output.c_str());
}

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
        HDF_LOGE("UsbfnMtpTest::WriteRandomDataToFile get random data failed");
        return false;
    }
    FILE *opFile = std::fopen(pathName.c_str(), "w");
    if (opFile == nullptr) {
        HDF_LOGE("UsbfnMtpTest::WriteRandomDataToFile create file failed: %{public}s", pathName.c_str());
        return false;
    }
    char buffer[GEN_FILE_BUF_SIZE];
    int64_t count = static_cast<int64_t>(fileSize);
    while (count > 0) {
        (void)memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
        int64_t readSize = count > GEN_FILE_BUF_SIZE ? GEN_FILE_BUF_SIZE : count;
        ssize_t readActual = read(random, static_cast<void *>(buffer), static_cast<size_t>(readSize));
        if (readActual != static_cast<ssize_t>(readSize)) {
            HDF_LOGW("UsbfnMtpTest::WriteRandomDataToFile read random failed");
            break;
        }
        size_t writeActual = std::fwrite(static_cast<void *>(buffer), 1, static_cast<size_t>(readSize), opFile);
        if (writeActual != static_cast<size_t>(readSize)) {
            HDF_LOGW("UsbfnMtpTest::WriteRandomDataToFile write failed");
            break;
        }
        count -= readSize;
    }
    std::fflush(opFile);
    std::fclose(opFile);
    close(random);
    HDF_LOGV("UsbfnMtpTest::WriteRandomDataToFile file %{public}s: %{public}" PRIu64 "/%{public}" PRIu64 "",
        pathName.c_str(), GetFileSize(pathName), fileSize);
    return count > 0 ? false : true;
}

bool GenerateFile(const std::string &pathName, int64_t fileSize)
{
    if (GetFileSize(pathName) == static_cast<uint64_t>(fileSize)) {
        HDF_LOGW("UsbfnMtpTest::GenerateFile file already exist");
        return true;
    }
    if (fileSize > GEN_FILE_LIMIT_512MB) {
        int32_t ret = truncate(pathName.c_str(), static_cast<off_t>(fileSize));
        if (ret != 0) {
            HDF_LOGE("UsbfnMtpTest::GenerateFile fail to truncate file to size: %{public}" PRId64 "", fileSize);
            return false;
        }
        HDF_LOGV("UsbfnMtpTest::GenerateFile truncate %{public}s %{public}" PRId64 "", pathName.c_str(), fileSize);
        return true;
    }
    return WriteRandomDataToFile(pathName, static_cast<uint64_t>(fileSize));
}

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbfnMtpTest::SetUpTestCase(void)
{
    // Selinux config this UT only works in directory WORKED_UT_PATH for open/read/write file for case send/recvfile.
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    std::cout << "===>please connect to PC use USB 3.0 interface, press enter to continue set function to mtp"
              << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    g_usbInterface = IUsbInterface::Get();
    ASSERT_TRUE(g_usbInterface != nullptr);
    auto ret = g_usbInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SINK, DATA_ROLE_DEVICE);
    sleep(SLEEP_TIME);
    ret = SwitchErrCode(ret);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->GetCurrentFunctions(g_currentFunc);
    ASSERT_EQ(0, ret);
    std::cout << "===>current function=" << g_currentFunc << ", set function to mtp, please wait" << std::endl;
    ret = g_usbInterface->SetCurrentFunctions(USB_FUNCTION_MTP);
    ASSERT_EQ(0, ret);

    g_usbfnMtpInterface = IUsbfnMtpInterface::Get();
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ret = g_usbfnMtpInterface->Start();
    ASSERT_EQ(0, ret);
}

void UsbfnMtpTest::TearDownTestCase(void)
{
    HDF_LOGV("UsbfnMtpTest::TearDownTestCase");
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    auto ret = g_usbfnMtpInterface->Stop();
    ASSERT_EQ(0, ret);
    ASSERT_TRUE(g_usbInterface != nullptr);
    ret = g_usbInterface->SetCurrentFunctions(g_currentFunc);
    ASSERT_EQ(0, ret);
    if (g_fileTestCount == 0) {
        return;
    }
    /* 1 means single test, run with '--gtest_filter=' option */
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
}

void UsbfnMtpTest::SetUp(void) {}

void UsbfnMtpTest::TearDown(void) {}

/**
 * @tc.name: UsbfnMtpRead001
 * @tc.desc: Test functions to Read
 * @tc.desc: int32_t Read(std::vector<uint8_t>& data);
 * @tc.desc: Positive test: parameters correctly, read length less then one packet size
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpRead001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpRead001 Case Start");
    std::vector<uint8_t> devData;

    std::cout << "UsbfnMtpRead001===>use libusb in PC launch bulk-out transfer(size=" << BULK_OUT_LESS_THEN_ONCE
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    int32_t ret = g_usbfnMtpInterface->Read(devData);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(devData.size(), static_cast<size_t>(BULK_OUT_LESS_THEN_ONCE));
}

/**
 * @tc.name: UsbfnMtpRead002
 * @tc.desc: Test functions to Read
 * @tc.desc: int32_t Read(std::vector<uint8_t>& data);
 * @tc.desc: Positive test: parameters correctly, read length exactly one packet size
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpRead002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpRead002 Case Start");
    std::vector<uint8_t> devData;

    std::cout << "UsbfnMtpRead002===>use libusb in PC launch bulk-out transfer(size=" << BULK_OUT_ONCE_MAX_SIZE
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    int32_t ret = g_usbfnMtpInterface->Read(devData);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(devData.size(), static_cast<size_t>(BULK_OUT_ONCE_MAX_SIZE));
}

/**
 * @tc.name: UsbfnMtpRead003
 * @tc.desc: Test functions to Read
 * @tc.desc: int32_t Read(std::vector<uint8_t>& data);
 * @tc.desc: Positive test: parameters correctly, read length more then one packet size, please read again
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpRead003, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpRead003 Case Start");
    std::vector<uint8_t> devData;

    std::cout << "UsbfnMtpRead003===>use libusb in PC launch bulk-out transfer(size=" << BULK_OUT_MORE_THEN_ONCE
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    int32_t ret = g_usbfnMtpInterface->Read(devData);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(devData.size(), static_cast<size_t>(BULK_OUT_ONCE_MAX_SIZE));
    devData.clear();
    ret = g_usbfnMtpInterface->Read(devData);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(devData.size(), static_cast<size_t>(BULK_OUT_MORE_THEN_ONCE - BULK_OUT_ONCE_MAX_SIZE));
}

/**
 * @tc.name: UsbfnMtpRead004
 * @tc.desc: Test functions to Read
 * @tc.desc: int32_t Read(std::vector<uint8_t>& data)
 * @tc.desc: Positive test: parameters correctly, no specific read size
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpRead004, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpRead004 Case Start");
    std::vector<uint8_t> devData;

    std::cout
        << "UsbfnMtpRead004===>use libusb in PC launch bulk-out transfer(size in [0, 1024]), press enter to continue"
        << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->Read(devData);
    EXPECT_EQ(ret, 0);
    EXPECT_GE(devData.size(), 0);
}

/**
 * @tc.name: UsbfnMtpRead005
 * @tc.desc: Test functions to Read
 * @tc.desc: int32_t Read(std::vector<uint8_t>& data)
 * @tc.desc: Positive test: parameters correctly, check read content
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpRead005, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpRead005 Case Start");
    std::vector<uint8_t> devData;
    // hex value of string "read005"
    std::vector<uint8_t> expectData = {0x72, 0x65, 0x61, 0x64, 0x30, 0x30, 0x35};

    std::cout << "UsbfnMtpRead005===>use libusb in PC launch bulk-out transfer(string=read005), press enter to continue"
              << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->Read(devData);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(devData, expectData);
    PrintVector("read005", devData, true);
}

/**
 * @tc.name: UsbfnMtpWrite001
 * @tc.desc: Test functions to Write
 * @tc.desc: int32_t Write(const std::vector<uint8_t>& data)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpWrite001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpWrite001 Case Start");
    uint32_t length = BULK_IN_LESS_THEN_ONCE;
    std::vector<uint8_t> devData;
    devData.assign(length, 'w');

    std::cout << "UsbfnMtpWrite001===>use libusb in PC launch bulk-in transfer(expect=" << length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->Write(devData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpWrite002
 * @tc.desc: Test functions to Write
 * @tc.desc: int32_t Write(const std::vector<uint8_t>& data)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpWrite002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpWrite002 Case Start");
    uint32_t length = BULK_IN_ONCE_MAX_SIZE;
    std::vector<uint8_t> devData;
    devData.assign(length, 'w');
    std::cout << "UsbfnMtpWrite002===>use libusb in PC launch bulk-in transfer(expect=" << length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->Write(devData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpWrite003
 * @tc.desc: Test functions to Write
 * @tc.desc: int32_t Write(const std::vector<uint8_t>& data)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpWrite003, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpWrite003 Case Start");
    uint32_t length = BULK_IN_MORE_THEN_ONCE;
    std::vector<uint8_t> devData;
    devData.assign(length, 'w');
    std::cout << "UsbfnMtpWrite003===>use libusb in PC launch bulk-in transfer(expect=" << length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->Write(devData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpWrite004
 * @tc.desc: Test functions to Write
 * @tc.desc: int32_t Write(const std::vector<uint8_t>& data)
 * @tc.desc: Positive test: parameters correctly, write empty data
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpWrite004, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpWrite004 Case Start");
    std::vector<uint8_t> devData;
    auto ret = g_usbfnMtpInterface->Write(devData);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpWrite005
 * @tc.desc: Test functions to Write
 * @tc.desc: int32_t Write(const std::vector<uint8_t>& data)
 * @tc.desc: Positive test: parameters correctly, write specific data
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpWrite005, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpWrite005 Case Start");
    // hex value of string "write005"
    std::vector<uint8_t> devData = {0x77, 0x72, 0x69, 0x74, 0x65, 0x30, 0x30, 0x35};
    std::cout << "UsbfnMtpWrite005===>use libusb in PC launch bulk-in transfer(expect string=write005), press enter "
                 "to continue"
              << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->Write(devData);
    EXPECT_EQ(ret, 0);
    PrintVector("write005", devData, true);
}

/**
 * @tc.name: UsbfnMtpSendEvent001
 * @tc.desc: Test functions to SendEvent
 * @tc.desc: int32_t SendEvent(const std::vector<uint8_t> &eventData);
 * @tc.desc: Positive test: parameters correctly, valid length
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpSendEvent001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpSendEvent001 Case Start");
    std::vector<uint8_t> devData;
    devData.assign(MTP_EVENT_PACKET_VALID_LEN, 'e');
    std::cout << "UsbfnMtpSendEvent001===>use libusb in PC launch intr-in transfer(expect=" << devData.size()
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->SendEvent(devData);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpSendEvent002
 * @tc.desc: Test functions to SendEvent
 * @tc.desc: int32_t SendEvent(const std::vector<uint8_t> &eventData);
 * @tc.desc: Positive test: parameters correctly, max length
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpSendEvent002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpSendEvent002 Case Start");
    std::vector<uint8_t> devData;
    devData.assign(MTP_EVENT_PACKET_MAX_BYTES, 'e');
    std::cout << "UsbfnMtpSendEvent002===>use libusb in PC launch intr-in transfer(expect=" << devData.size()
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    auto ret = g_usbfnMtpInterface->SendEvent(devData);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpSendEvent003
 * @tc.desc: Test functions to SendEvent
 * @tc.desc: int32_t SendEvent(const std::vector<uint8_t> &eventData);
 * @tc.desc: Negative test: parameters exception, size overflow
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpSendEvent003, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpSendEvent003 Case Start");
    std::vector<uint8_t> devData;
    devData.assign(MTP_EVENT_PACKET_INVALID_LEN, 'e');
    std::cout << "UsbfnMtpSendEvent003===>use libusb in PC launch intr-in transfer(expect=no data, or error), press "
                 "enter to continue"
              << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    auto ret = g_usbfnMtpInterface->SendEvent(devData);
    EXPECT_NE(0, ret);
    std::cout << "UsbfnMtpSendEvent003===>make sure transfer timeout in PC, then start next test " << std::endl;
}

/**
 * @tc.name: UsbfnMtpSendEvent004
 * @tc.desc: Test functions to SendEvent
 * @tc.desc: int32_t SendEvent(const std::vector<uint8_t> &eventData);
 * @tc.desc: Positive test: parameters correctly, max length, check content
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpSendEvent004, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpSendEvent004 Case Start");
    // hex value of string "event004"
    std::vector<uint8_t> devData = {0x65, 0x76, 0x65, 0x6E, 0x74, 0x30, 0x30, 0x34};
    std::cout << "UsbfnMtpSendEvent004===>use libusb in PC launch intr-in transfer(expect string=event004), press "
                 "enter to continue"
              << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    auto ret = g_usbfnMtpInterface->SendEvent(devData);
    EXPECT_EQ(0, ret);
    PrintVector("event004", devData, true);
}

/**
 * @tc.name: UsbfnMtpFileReceive001
 * @tc.desc: Test functions to ReceiveFile
 * @tc.desc: int32_t ReceiveFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, one packet enough
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileReceive001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileReceive001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_OUT_LESS_THEN_ONCE;
    std::cout << "UsbfnMtpFileReceive001===>use libusb in PC launch bulk-out transfer(size = " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(GetFileSize(filePathName), static_cast<uint64_t>(mfs.length));
}

/**
 * @tc.name: UsbfnMtpFileReceive002
 * @tc.desc: Test functions to ReceiveFile
 * @tc.desc: int32_t ReceiveFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, zero length
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileReceive002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileReceive002 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = 0;
    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(GetFileSize(filePathName), static_cast<uint64_t>(mfs.length));
}

/**
 * @tc.name: UsbfnMtpFileReceive003
 * @tc.desc: Test functions to ReceiveFile
 * @tc.desc: int32_t ReceiveFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, one normal packet + short packet
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileReceive003, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileReceive003 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_OUT_MORE_THEN_ONCE;
    std::cout << "UsbfnMtpFileReceive003===>use libusb in PC launch bulk-out transfer(size = " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(GetFileSize(filePathName), static_cast<uint64_t>(mfs.length));
}

/**
 * @tc.name: UsbfnMtpFileReceive004
 * @tc.desc: Test functions to ReceiveFile
 * @tc.desc: int32_t ReceiveFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: mfs.length set to max, 12 packet + ZLP
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileReceive004, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileReceive004 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = MTP_FILE_SIZE_REUSE_REQ;
    std::cout << "UsbfnMtpFileReceive004===>use libusb in PC launch bulk-out transfer(size = " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(GetFileSize(filePathName), static_cast<uint64_t>(mfs.length));
}

/**
 * @tc.name: UsbfnMtpFileReceive005
 * @tc.desc: Test functions to ReceiveFile
 * @tc.desc: int32_t ReceiveFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, command and transactionId ignored
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileReceive005, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileReceive005 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_OUT_LESS_THEN_ONCE;
    mfs.command = CMD_CODE_GET_DEVICE_INFO;
    mfs.transactionId = TRANSACTION_ID_RANDOM;
    std::cout << "UsbfnMtpFileReceive005===>use libusb in PC launch bulk-out transfer(size = " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(GetFileSize(filePathName), static_cast<uint64_t>(mfs.length));
}

/**
 * @tc.name: UsbfnMtpFileReceive006
 * @tc.desc: Test functions to ReceiveFile
 * @tc.desc: int32_t ReceiveFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: mfs.length set to max, recv actual file size depend on xfer count
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileReceive006, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileReceive006 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = MTP_MAX_FILE_SIZE;
    std::cout
        << "UsbfnMtpFileReceive006===>use libusb in PC launch bulk-out transfer(size = any), press enter to continue"
        << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
    EXPECT_GE(GetFileSize(filePathName), 0);
}

/**
 * @tc.name: UsbfnMtpFileReceive007
 * @tc.desc: Test functions to ReceiveFile
 * @tc.desc: int32_t ReceiveFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: mfs.length set to max - 1: 4GB - 2
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileReceive007, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileReceive007 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = MTP_MAX_FILE_SIZE - 1;
    std::cout << "UsbfnMtpFileReceive007===>use libusb in PC launch bulk-out transfer(size = " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(GetFileSize(filePathName), static_cast<uint64_t>(mfs.length));
}

/**
 * @tc.name: UsbfnMtpFileReceive008
 * @tc.desc: Test functions to ReceiveFile
 * @tc.desc: int32_t ReceiveFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: mfs.length set to max + 1: 4GB
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileReceive008, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileReceive008 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = MTP_MAX_FILE_SIZE + 1;
    std::cout << "UsbfnMtpFileReceive008===>use libusb in PC launch bulk-out transfer(size = " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(GetFileSize(filePathName), static_cast<uint64_t>(mfs.length));
}

/**
 * @tc.name: UsbfnMtpFileReceive009
 * @tc.desc: Test functions to ReceiveFile
 * @tc.desc: int32_t ReceiveFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: mfs.length set to max + 2: 4GB + 1
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileReceive009, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileReceive009 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = MTP_MAX_FILE_SIZE + 2;
    std::cout << "UsbfnMtpFileReceive009===>use libusb in PC launch bulk-out transfer(size = " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    std::string filePathName = MTP_TEST_RECV_FILE;
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->ReceiveFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(GetFileSize(filePathName), static_cast<uint64_t>(mfs.length));
}

/**
 * @tc.name: UsbfnMtpFileSend001
 * @tc.desc: Test functions to SendFile
 * @tc.desc: int32_t SendFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly， length in one packet
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileSend001, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileSend001 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_IN_LESS_THEN_ONCE;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpFileSend001===>use libusb in PC launch bulk-in transfer(expect " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: UsbfnMtpFileSend002
 * @tc.desc: Test functions to SendFile
 * @tc.desc: int32_t SendFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, send header + data in one packet
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileSend002, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileSend002 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = BULK_IN_LESS_THEN_ONCE;
    mfs.command = CMD_CODE_GET_DEVICE_INFO;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpFileSend002===>use libusb in PC launch bulk-in transfer(expect "
              << mfs.length + MTP_PACKET_HEADER_SIZE << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileSend003
 * @tc.desc: Test functions to SendFile
 * @tc.desc: int32_t SendFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, zero length
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileSend003, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileSend003 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = 0;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileSend004
 * @tc.desc: Test functions to SendFile
 * @tc.desc: int32_t SendFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, send header + data in two packet: normal + short
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileSend004, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileSend004 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = MTP_FILE_SIZE_ONE_REQ;
    mfs.command = CMD_CODE_GET_DEVICE_INFO;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpFileSend004===>use libusb in PC launch bulk-in transfer(expect "
              << mfs.length + MTP_PACKET_HEADER_SIZE << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileSend005
 * @tc.desc: Test functions to SendFile
 * @tc.desc: int32_t SendFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, mfs.length set to max
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileSend005, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileSend005 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = MTP_FILE_SIZE_REUSE_REQ;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpFileSend005===>use libusb in PC launch bulk-in transfer(speed, expect " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileSend006
 * @tc.desc: Test functions to SendFile
 * @tc.desc: int32_t SendFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, mfs.length set to max: 4GB - 1
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileSend006, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileSend006 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = MTP_MAX_FILE_SIZE;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpFileSend006===>use libusb in PC launch bulk-in transfer(speed, expect " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileSend007
 * @tc.desc: Test functions to SendFile
 * @tc.desc: int32_t SendFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, mfs.length set to max + 1: 4GB
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileSend007, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileSend007 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = MTP_MAX_FILE_SIZE + 1;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpFileSend007===>use libusb in PC launch bulk-in transfer(speed, expect " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbfnMtpFileSend008
 * @tc.desc: Test functions to SendFile
 * @tc.desc: int32_t SendFile(const UsbFnMtpFileSlice &mfs);
 * @tc.desc: Positive test: parameters correctly, mfs.length set to max + 1: 4GB + 1
 * @tc.type: FUNC
 */
HWTEST_F(UsbfnMtpTest, UsbfnMtpFileSend008, TestSize.Level1)
{
    ASSERT_TRUE(g_usbfnMtpInterface != nullptr);
    ASSERT_TRUE(GetCurrentProcPath() == std::string(WORKED_UT_PATH));
    HDF_LOGI("UsbfnMtpTest::UsbfnMtpFileSend008 Case Start");
    g_fileTestCount++;
    struct UsbFnMtpFileSlice mfs = g_mfs;
    mfs.length = MTP_MAX_FILE_SIZE + 2;
    std::string filePathName = MTP_TEST_SEND_FILE;
    EXPECT_TRUE(GenerateFile(filePathName, mfs.length));
    std::cout << "UsbfnMtpFileSend008===>use libusb in PC launch bulk-in transfer(speed, expect " << mfs.length
              << "), press enter to continue" << std::endl;
    int32_t c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    mfs.fd = open(filePathName.c_str(), O_CREAT | O_RDONLY);
    EXPECT_GT(mfs.fd, 0);
    auto ret = g_usbfnMtpInterface->SendFile(mfs);
    close(mfs.fd);
    EXPECT_EQ(0, ret);
}

} // namespace
