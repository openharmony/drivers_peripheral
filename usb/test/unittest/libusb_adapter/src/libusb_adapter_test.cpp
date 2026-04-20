/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "libusb_adapter_test.h"

#include <iostream>
#include <memory>
#include <vector>

#include "hdf_log.h"
#include "v1_2/iusb_interface.h"
#include "v1_2/usb_types.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_2;

const int SLEEP_TIME = 3;
const uint8_t BUS_NUM_INVALID = 255;
const uint8_t DEV_ADDR_INVALID = 255;
const uint8_t INTERFACE_ID_INVALID = 32;
UsbDev LibusbAdapterTest::dev_ = {0, 0};

namespace {
sptr<OHOS::HDI::Usb::V1_2::IUsbInterface> g_usbInterface = nullptr;
std::shared_ptr<LibusbAdapter> g_libusbAdapter = nullptr;

void LibusbAdapterTest::SetUpTestCase(void)
{
    g_usbInterface = OHOS::HDI::Usb::V1_2::IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    g_libusbAdapter = LibusbAdapter::GetInstance();
    if (g_libusbAdapter == nullptr) {
        HDF_LOGE("%{public}s: LibusbAdapter::GetInstance() failed", __func__);
        exit(0);
    }
    auto ret = g_usbInterface->SetPortRole(1, 1, 1);
    sleep(SLEEP_TIME);
    HDF_LOGI("LibusbAdapterTest::[Device] %{public}d SetPortRole=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    if (ret != 0) {
        exit(0);
    }
    std::cout << "please connect device, press enter to continue" << std::endl;
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    dev_ = {1, 2};
}

void LibusbAdapterTest::TearDownTestCase(void)
{
    g_libusbAdapter = nullptr;
}

void LibusbAdapterTest::SetUp(void) {}

void LibusbAdapterTest::TearDown(void) {}

/**
 * @tc.name: LibusbAdapter001
 * @tc.desc: Test functions to GetInstance
 * @tc.desc: std::shared_ptr<LibusbAdapter> GetInstance();
 * @tc.desc: Positive test: get singleton instance
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetInstance001, TestSize.Level1)
{
    auto instance = LibusbAdapter::GetInstance();
    ASSERT_NE(nullptr, instance);
}

/**
 * @tc.name: LibusbAdapter002
 * @tc.desc: Test functions to GetInstance
 * @tc.desc: std::shared_ptr<LibusbAdapter> GetInstance();
 * @tc.desc: Positive test: verify singleton
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetInstance002, TestSize.Level1)
{
    auto instance1 = LibusbAdapter::GetInstance();
    auto instance2 = LibusbAdapter::GetInstance();
    ASSERT_EQ(instance1, instance2);
}

/**
 * @tc.name: LibusbAdapterOpenDevice001
 * @tc.desc: Test functions to OpenDevice
 * @tc.desc: int32_t OpenDevice(const UsbDev &dev);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterOpenDevice001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterOpenDevice002
 * @tc.desc: Test functions to OpenDevice
 * @tc.desc: int32_t OpenDevice(const UsbDev &dev);
 * @tc.desc: Negative test: invalid bus number
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterOpenDevice002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterOpenDevice003
 * @tc.desc: Test functions to OpenDevice
 * @tc.desc: int32_t OpenDevice(const UsbDev &dev);
 * @tc.desc: Negative test: invalid device address
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterOpenDevice003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterCloseDevice001
 * @tc.desc: Test functions to CloseDevice
 * @tc.desc: int32_t CloseDevice(const UsbDev &dev, bool isDetach);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterCloseDevice001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->CloseDevice(dev, false);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d CloseDevice result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: LibusbAdapterCloseDevice002
 * @tc.desc: Test functions to CloseDevice
 * @tc.desc: int32_t CloseDevice(const UsbDev &dev, bool isDetach);
 * @tc.desc: Negative test: close without open
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterCloseDevice002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->CloseDevice(dev, false);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d CloseDevice result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterResetDevice001
 * @tc.desc: Test functions to ResetDevice
 * @tc.desc: int32_t ResetDevice(const UsbDev &dev);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterResetDevice001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ResetDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ResetDevice result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterResetDevice002
 * @tc.desc: Test functions to ResetDevice
 * @tc.desc: int32_t ResetDevice(const UsbDev &dev);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterResetDevice002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_libusbAdapter->ResetDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ResetDevice result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterGetDeviceDescriptor001
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetDeviceDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> descriptor;
    auto ret = g_libusbAdapter->GetDeviceDescriptor(dev, descriptor);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetDeviceDescriptor result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    EXPECT_GT(descriptor.size(), 0);
}

/**
 * @tc.name: LibusbAdapterGetDeviceDescriptor002
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetDeviceDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> descriptor;
    auto ret = g_libusbAdapter->GetDeviceDescriptor(dev, descriptor);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetDeviceDescriptor result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterGetConfigDescriptor001
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetConfigDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> descriptor;
    auto ret = g_libusbAdapter->GetConfigDescriptor(dev, 0, descriptor);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetConfigDescriptor result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    EXPECT_GT(descriptor.size(), 0);
}

/**
 * @tc.name: LibusbAdapterGetConfigDescriptor002
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetConfigDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> descriptor;
    auto ret = g_libusbAdapter->GetConfigDescriptor(dev, 0, descriptor);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetConfigDescriptor result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterGetStringDescriptor001
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetStringDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> descriptor;
    auto ret = g_libusbAdapter->GetStringDescriptor(dev, 1, descriptor);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetStringDescriptor result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: LibusbAdapterGetStringDescriptor002
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetStringDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> descriptor;
    auto ret = g_libusbAdapter->GetStringDescriptor(dev, 1, descriptor);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetStringDescriptor result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterSetConfig001
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterSetConfig001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->SetConfig(dev, 1);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d SetConfig result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterSetConfig002
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterSetConfig002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_libusbAdapter->SetConfig(dev, 1);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d SetConfig result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterGetConfig001
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetConfig001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    uint8_t configIndex = 0;
    ret = g_libusbAdapter->GetConfig(dev, configIndex);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetConfig result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterGetConfig002
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetConfig002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    uint8_t configIndex = 0;
    auto ret = g_libusbAdapter->GetConfig(dev, configIndex);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetConfig result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterClaimInterface001
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t ClaimInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t force);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterClaimInterface001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    g_libusbAdapter->ReleaseInterface(dev, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterClaimInterface002
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t ClaimInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t force);
 * @tc.desc: Negative test: invalid interface id
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterClaimInterface002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, INTERFACE_ID_INVALID, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterReleaseInterface001
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterReleaseInterface001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ReleaseInterface(dev, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ReleaseInterface result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterReleaseInterface002
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: invalid interface id
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterReleaseInterface002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ReleaseInterface(dev, INTERFACE_ID_INVALID);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ReleaseInterface result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterSetInterface001
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterSetInterface001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->SetInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d SetInterface result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    g_libusbAdapter->ReleaseInterface(dev, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterSetInterface002
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterSetInterface002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_libusbAdapter->SetInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d SetInterface result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterGetDeviceSpeed001
 * @tc.desc: Test functions to GetDeviceSpeed
 * @tc.desc: int32_t GetDeviceSpeed(const UsbDev &dev, uint8_t &speed);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetDeviceSpeed001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t speed = 0;
    auto ret = g_libusbAdapter->GetDeviceSpeed(dev, speed);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetDeviceSpeed result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: LibusbAdapterGetDeviceSpeed002
 * @tc.desc: Test functions to GetDeviceSpeed
 * @tc.desc: int32_t GetDeviceSpeed(const UsbDev &dev, uint8_t &speed);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetDeviceSpeed002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    uint8_t speed = 0;
    auto ret = g_libusbAdapter->GetDeviceSpeed(dev, speed);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetDeviceSpeed result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterGetFileDescriptor001
 * @tc.desc: Test functions to GetFileDescriptor
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetFileDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t fd = -1;
    auto ret = g_libusbAdapter->GetFileDescriptor(dev, fd);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetFileDescriptor result=%{public}d, fd=%{public}d", __LINE__, ret, fd);
    EXPECT_EQ(0, ret);
    EXPECT_GE(fd, 0);
    if (fd >= 0) {
        close(fd);
    }
}

/**
 * @tc.name: LibusbAdapterGetFileDescriptor002
 * @tc.desc: Test functions to GetFileDescriptor
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetFileDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    int32_t fd = -1;
    auto ret = g_libusbAdapter->GetFileDescriptor(dev, fd);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetFileDescriptor result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterClearHalt001
 * @tc.desc: Test functions to ClearHalt
 * @tc.desc: int32_t ClearHalt(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterClearHalt001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbPipe pipe = {0, 0x81};
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClearHalt(dev, pipe);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClearHalt result=%{public}d", __LINE__, ret);
    g_libusbAdapter->ReleaseInterface(dev, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterManageInterface001
 * @tc.desc: Test functions to ManageInterface
 * @tc.desc: int32_t ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterManageInterface001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ManageInterface(dev, 0, true);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ManageInterface result=%{public}d", __LINE__, ret);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterControlTransferRead001
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, const UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterControlTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbCtrlTransfer ctrl = {0x80, 0x06, 0x0100, 0x00, 1000};
    std::vector<uint8_t> data;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ControlTransferRead(dev, ctrl, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ControlTransferRead result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterControlTransferRead002
 * @tc.desc: Test functions to ControlTransferRead
 * @tc.desc: int32_t ControlTransferRead(const UsbDev &dev, const UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterControlTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    struct UsbCtrlTransfer ctrl = {0x80, 0x06, 0x0100, 0x00, 1000};
    std::vector<uint8_t> data;
    auto ret = g_libusbAdapter->ControlTransferRead(dev, ctrl, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ControlTransferRead result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterControlTransferWrite001
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, const UsbCtrlTransfer &ctrl, const std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterControlTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbCtrlTransfer ctrl = {0x00, 0x09, 0x0001, 0x00, 1000};
    std::vector<uint8_t> data = {0x00};
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ControlTransferWrite(dev, ctrl, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ControlTransferWrite result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterControlTransferWrite002
 * @tc.desc: Test functions to ControlTransferWrite
 * @tc.desc: int32_t ControlTransferWrite(const UsbDev &dev, const UsbCtrlTransfer &ctrl, const std::vector<uint8_t> &data);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterControlTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    struct UsbCtrlTransfer ctrl = {0x00, 0x09, 0x0001, 0x00, 1000};
    std::vector<uint8_t> data = {0x00};
    auto ret = g_libusbAdapter->ControlTransferWrite(dev, ctrl, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ControlTransferWrite result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterBulkTransferRead001
 * @tc.desc: Test functions to BulkTransferRead
 * @tc.desc: int32_t BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterBulkTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbPipe pipe = {0, 0x81};
    std::vector<uint8_t> data;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->BulkTransferRead(dev, pipe, 1000, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d BulkTransferRead result=%{public}d", __LINE__, ret);
    g_libusbAdapter->ReleaseInterface(dev, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterBulkTransferRead002
 * @tc.desc: Test functions to BulkTransferRead
 * @tc.desc: int32_t BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data);
 * @tc.desc: Negative test: invalid interface id
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterBulkTransferRead002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbPipe pipe = {INTERFACE_ID_INVALID, 0x81};
    std::vector<uint8_t> data;
    auto ret = g_libusbAdapter->BulkTransferRead(dev, pipe, 1000, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d BulkTransferRead result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterBulkTransferWrite001
 * @tc.desc: Test functions to BulkTransferWrite
 * @tc.desc: int32_t BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterBulkTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbPipe pipe = {0, 0x01};
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->BulkTransferWrite(dev, pipe, 1000, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d BulkTransferWrite result=%{public}d", __LINE__, ret);
    g_libusbAdapter->ReleaseInterface(dev, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterBulkTransferWrite002
 * @tc.desc: Test functions to BulkTransferWrite
 * @tc.desc: int32_t BulkTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data);
 * @tc.desc: Negative test: invalid interface id
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterBulkTransferWrite002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbPipe pipe = {INTERFACE_ID_INVALID, 0x01};
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    auto ret = g_libusbAdapter->BulkTransferWrite(dev, pipe, 1000, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d BulkTransferWrite result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: LibusbAdapterInterruptTransferRead001
 * @tc.desc: Test functions to InterruptTransferRead
 * @tc.desc: int32_t InterruptTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterInterruptTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbPipe pipe = {0, 0x81};
    std::vector<uint8_t> data;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->InterruptTransferRead(dev, pipe, 1000, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d InterruptTransferRead result=%{public}d", __LINE__, ret);
    g_libusbAdapter->ReleaseInterface(dev, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterInterruptTransferWrite001
 * @tc.desc: Test functions to InterruptTransferWrite
 * @tc.desc: int32_t InterruptTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterInterruptTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbPipe pipe = {0, 0x01};
    std::vector<uint8_t> data = {0x01, 0x02};
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->InterruptTransferWrite(dev, pipe, 1000, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d InterruptTransferWrite result=%{public}d", __LINE__, ret);
    g_libusbAdapter->ReleaseInterface(dev, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterIsoTransferRead001
 * @tc.desc: Test functions to IsoTransferRead
 * @tc.desc: int32_t IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterIsoTransferRead001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbPipe pipe = {0, 0x81};
    std::vector<uint8_t> data;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->IsoTransferRead(dev, pipe, 1000, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d IsoTransferRead result=%{public}d", __LINE__, ret);
    g_libusbAdapter->ReleaseInterface(dev, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterIsoTransferWrite001
 * @tc.desc: Test functions to IsoTransferWrite
 * @tc.desc: int32_t IsoTransferWrite(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterIsoTransferWrite001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    struct UsbPipe pipe = {0, 0x01};
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->IsoTransferWrite(dev, pipe, 1000, data);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d IsoTransferWrite result=%{public}d", __LINE__, ret);
    g_libusbAdapter->ReleaseInterface(dev, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterGetCurrentInterfaceSetting001
 * @tc.desc: Test functions to GetCurrentInterfaceSetting
 * @tc.desc: int32_t GetCurrentInterfaceSetting(const UsbDev &dev, uint8_t &settingIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetCurrentInterfaceSetting001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t settingIndex = 0;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->ClaimInterface(dev, 0, 0);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d ClaimInterface result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->GetCurrentInterfaceSetting(dev, settingIndex);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetCurrentInterfaceSetting result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    g_libusbAdapter->ReleaseInterface(dev, 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterGetRawDescriptor001
 * @tc.desc: Test functions to GetRawDescriptor
 * @tc.desc: int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetRawDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> descriptor;
    auto ret = g_libusbAdapter->OpenDevice(dev);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d OpenDevice result=%{public}d", __LINE__, ret);
    ASSERT_EQ(0, ret);
    ret = g_libusbAdapter->GetRawDescriptor(dev, descriptor);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetRawDescriptor result=%{public}d", __LINE__, ret);
    EXPECT_EQ(0, ret);
    EXPECT_GT(descriptor.size(), 0);
    g_libusbAdapter->CloseDevice(dev);
}

/**
 * @tc.name: LibusbAdapterGetRawDescriptor002
 * @tc.desc: Test functions to GetRawDescriptor
 * @tc.desc: int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: invalid device
 * @tc.type: FUNC
 */
HWTEST_F(LibusbAdapterTest, LibusbAdapterGetRawDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> descriptor;
    auto ret = g_libusbAdapter->GetRawDescriptor(dev, descriptor);
    HDF_LOGI("LibusbAdapterTest:: Line:%{public}d GetRawDescriptor result=%{public}d", __LINE__, ret);
    EXPECT_NE(ret, 0);
}
} // namespace
