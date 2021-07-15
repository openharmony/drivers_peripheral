/*
 * UsbDeviceNetFuncTest.cpp
 *
 * usb net device function test source file
 *
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#include <cstdio>
#include <unistd.h>
#include <gtest/gtest.h>

using namespace std;
using namespace testing::ext;

namespace {
class UsbDeviceNetFuncTest : public testing::Test {
protected:
    static void SetUpTestCase(void)
    {
        printf("------start UsbDeviceNetFuncTest------\n");
    }
    static void TearDownTestCase(void)
    {
        printf("------end UsbDeviceNetFuncTest------\n");
    }
};

/**
 * @tc.number    : ping
 * @tc.name      : 验证能否ping通网卡
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbDeviceNetFuncTest, UsbDevicePing_001, TestSize.Level1)
{
    printf("------start UsbDevicePing_001------\n");
    EXPECT_EQ(system("level_ip -c 10 10.0.0.10"), 0);
    printf("------end UsbDevicePing_001------\n");
}

/**
 * @tc.number    : ping
 * @tc.name      : 验证发送不同大小字节ping网卡是否有异常
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbDeviceNetFuncTest, UsbDevicePing_002, TestSize.Level1)
{
    printf("------start UsbDevicePing_002------\n");
    EXPECT_EQ(system("level_ip -s 8 -c 5 10.0.0.10"), 0);
    EXPECT_EQ(system("level_ip -s 100 -c 5 10.0.0.10"), 0);
    EXPECT_EQ(system("level_ip -s 400 -c 5 10.0.0.10"), 0);
    printf("------end UsbDevicePing_002------\n");
}

/**
 * @tc.number    : ping
 * @tc.name      : 验证多次ping网卡是否有异常
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbDeviceNetFuncTest, UsbDevicePing_003, TestSize.Level1)
{
    printf("------start UsbDevicePing_003------\n");
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(system("level_ip -c 5 10.0.0.10"), 0);
    }
    printf("------end UsbDevicePing_003------\n");
}

/**
 * @tc.number    : H_Lx_D_Sub_usb_DFR_001
 * @tc.name      : 验证进程被杀掉后SDK自启动功能
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbDeviceNetFuncTest, KillDeviceSdkProcess, TestSize.Level1)
{
    printf("------start KillDeviceSdkProcess------\n");
    ASSERT_EQ(system("kill $(pidof usbfnMaster_host)"), 0);
    printf("Please waiting for restarting sdk process...\n");
    sleep(10);
    printf("Please restart host_level_ip in 20s!\n");
    sleep(20);
    EXPECT_EQ(system("level_ip -c 5 10.0.0.10"), 0);
    printf("------end KillDeviceSdkProcess------\n");
}
}