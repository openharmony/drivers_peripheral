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

#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>
#include <unistd.h>
#include "usb_device_info_parser.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "hdf_base.h"
#include "hdf_log.h"
#include "osal_mem.h"
#include "osal_time.h"
#include "securec.h"
#include "usb_ddk_interface.h"
#include "ddk_sysfs_device.h"

using namespace std;
using namespace testing::ext;
namespace {
class DdkSysfsDeviceTest : public testing::Test {
};

/**
 * @tc.number    : DdkSysfsGetDevNameTestForHidraw001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(DdkSysfsDeviceTest, DdkSysfsGetDevNameTestForHidraw001, TestSize.Level1)
{
    UsbDeviceInfoParser parser;
    std::optional<UsbDeviceInfo> dev = parser.Find("USB Optical Mouse");
    if (!dev.has_value()) {
        std::cout << "DdkGetDevInfos failed!" << std::endl;
        return;
    }

    std::cout << "busNum:" << dev.value().busNum << " devNum:" << dev.value().devNum << std::endl;
    DevInterfaceInfo devInfo;
    devInfo.busNum = dev.value().busNum;
    devInfo.devNum = dev.value().devNum;
    devInfo.intfNum = 0;
    char devNodePath[NAME_MAX] = { 0x00 };
    int32_t ret = DdkSysfsGetDevNodePath(&devInfo, "hidraw", devNodePath, sizeof(devNodePath));
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ("/dev/hidraw0", std::string(devNodePath));
}

/**
 * @tc.number    : DdkSysfsGetDevNameTestForHidraw002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(DdkSysfsDeviceTest, DdkSysfsGetDevNameTestForHidraw002, TestSize.Level1)
{
    UsbDeviceInfoParser parser;
    std::optional<UsbDeviceInfo> dev = parser.Find("USB (Serial|UART)");
    if (!dev.has_value()) {
        std::cout << "DdkGetDevInfos failed!" << std::endl;
        return;
    }

    std::cout << "busNum:" << dev.value().busNum << " devNum:" << dev.value().devNum << std::endl;
    DevInterfaceInfo devInfo;
    devInfo.busNum = dev.value().busNum;
    devInfo.devNum = dev.value().devNum;
    devInfo.intfNum = 0;
    char devNodePath[NAME_MAX] = { 0x00 };
    int32_t ret = DdkSysfsGetDevNodePath(&devInfo, "hidraw", devNodePath, sizeof(devNodePath));
    EXPECT_EQ(HDF_ERR_OUT_OF_RANGE, ret);
}

/**
 * @tc.number    : DdkSysfsGetDevNameTestForHidraw003
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(DdkSysfsDeviceTest, DdkSysfsGetDevNameTestForHidraw003, TestSize.Level1)
{
    UsbDeviceInfoParser parser;
    std::optional<UsbDeviceInfo> dev = parser.Find("USB Optical Mouse");
    if (!dev.has_value()) {
        std::cout << "DdkGetDevInfos failed!" << std::endl;
        return;
    }

    std::cout << "busNum:" << dev.value().busNum << " devNum:" << dev.value().devNum << std::endl;
    DevInterfaceInfo devInfo;
    devInfo.busNum = dev.value().busNum;
    devInfo.devNum = dev.value().devNum;
    devInfo.intfNum = 2;
    char devNodePath[NAME_MAX] = { 0x00 };
    int32_t ret = DdkSysfsGetDevNodePath(&devInfo, "hidraw", devNodePath, sizeof(devNodePath));
    EXPECT_EQ(HDF_ERR_OUT_OF_RANGE, ret);
}

/**
 * @tc.number    : DdkSysfsGetDevNameTestForUsbSerial001
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(DdkSysfsDeviceTest, DdkSysfsGetDevNameTestForUsbSerial001, TestSize.Level1)
{
    UsbDeviceInfoParser parser;
    std::optional<UsbDeviceInfo> dev = parser.Find("USB Serial");
    if (!dev.has_value()) {
        std::cout << "DdkGetDevInfos failed!" << std::endl;
        return;
    }

    std::cout << "busNum:" << dev.value().busNum << " devNum:" << dev.value().devNum << std::endl;
    DevInterfaceInfo devInfo;
    devInfo.busNum = dev.value().busNum;
    devInfo.devNum = dev.value().devNum;
    devInfo.intfNum = 0;
    char devNodePath[NAME_MAX] = { 0x00 };
    int32_t ret = DdkSysfsGetDevNodePath(&devInfo, "ttyUSB", devNodePath, sizeof(devNodePath));
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ("/dev/ttyUSB0", std::string(devNodePath));
}

/**
 * @tc.number    : DdkSysfsGetDevNameTestForUsbSerial002
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(DdkSysfsDeviceTest, DdkSysfsGetDevNameTestForUsbSerial002, TestSize.Level1)
{
    UsbDeviceInfoParser parser;
    std::optional<UsbDeviceInfo> dev = parser.Find("USB Optical Mouse");
    if (!dev.has_value()) {
        std::cout << "DdkGetDevInfos failed!" << std::endl;
        return;
    }

    std::cout << "busNum:" << dev.value().busNum << " devNum:" << dev.value().devNum << std::endl;
    DevInterfaceInfo devInfo;
    devInfo.busNum = dev.value().busNum;
    devInfo.devNum = dev.value().devNum;
    devInfo.intfNum = 0;
    char devNodePath[NAME_MAX] = { 0x00 };
    int32_t ret = DdkSysfsGetDevNodePath(&devInfo, "ttyUSB", devNodePath, sizeof(devNodePath));
    EXPECT_EQ(HDF_ERR_OUT_OF_RANGE, ret);
}

/**
 * @tc.number    : DdkSysfsGetDevNameTestForUsbSerial003
 * @tc.name      :
 * @tc.type      : PERF
 * @tc.level     : Level 1
 */
HWTEST_F(DdkSysfsDeviceTest, DdkSysfsGetDevNameTestForUsbSerial003, TestSize.Level1)
{
    UsbDeviceInfoParser parser;
    std::optional<UsbDeviceInfo> dev = parser.Find("USB Serial");
    if (!dev.has_value()) {
        std::cout << "DdkGetDevInfos failed!" << std::endl;
        return;
    }

    std::cout << "busNum:" << dev.value().busNum << " devNum:" << dev.value().devNum << std::endl;
    DevInterfaceInfo devInfo;
    devInfo.busNum = dev.value().busNum;
    devInfo.devNum = dev.value().devNum;
    devInfo.intfNum = 2;
    char devNodePath[NAME_MAX] = { 0x00 };
    int32_t ret = DdkSysfsGetDevNodePath(&devInfo, "ttyUSB", devNodePath, sizeof(devNodePath));
    EXPECT_EQ(HDF_ERR_OUT_OF_RANGE, ret);
}

} // namespace
