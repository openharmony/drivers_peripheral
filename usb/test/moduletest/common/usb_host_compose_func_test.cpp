/*
 * UsbHostComposeDeviceFuncTest.cpp
 *
 * usb compose device function test source file
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
#include <cstring>
#include <unistd.h>
#include <gtest/gtest.h>
#include "usb_utils.h"

using namespace std;
using namespace testing::ext;

namespace {
const string WLOG_FILE = "/data/acm_write_xts";
const string RLOG_FILE = "/data/acm_read_xts";

class UsbHostComposeDeviceFuncTest : public testing::Test {
protected:
    static void SetUpTestCase(void)
    {
        printf("------start UsbHostComposeDeviceFuncTest------\n");
        system("cat /dev/null > /data/acm_write_xts");
        system("cat /dev/null > /data/acm_read_xts");
    }
    static void TearDownTestCase(void)
    {
        printf("------end UsbHostComposeDeviceFuncTest------\n");
    }
};

/**
 * @tc.number    : H_Lx_H_Sub_usb_IO read_002，H_Lx_H_Sub_usb_IO read_008
 * @tc.name      : 验证复合设备串口的数据读写
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostComposeDeviceFuncTest, UsbHostSerialIOTest_001, TestSize.Level1)
{
    printf("------start UsbHostSerialIOTest_001------\n");
    ASSERT_EQ(system("hostacm_moduletest -SDK -syncRead &"), 0) << "ErrInfo:  failed to start syncRead";
    const string data = "abc123";
    double startTs = GetNowTs();
    string wlog, rlog;
    ASSERT_EQ(system(("hostacm_moduletest -SDK -syncWrite '" + data + "'").c_str()), 0);
    wlog = "send data[" + data + "] to device";
    rlog = "recv data[" + data + "] from device";
    sleep(2);
    EXPECT_TRUE(HasLog(wlog, startTs, WLOG_FILE));
    EXPECT_TRUE(HasLog(rlog, startTs, RLOG_FILE));
    printf("------end UsbHostSerialIOTest_001------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IO read_002，H_Lx_H_Sub_usb_IO read_008
 * @tc.name      : 验证复合设备串口的数据读写
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostComposeDeviceFuncTest, UsbHostSerialIOTest_002, TestSize.Level1)
{
    printf("------start UsbHostSerialIOTest_002------\n");
    ASSERT_EQ(system("hostacm_moduletest -SDK -asyncRead &"), 0) << "ErrInfo:  failed to start asyncRead";
    sleep(2);
    const string data[] = {
        "0123456789",
        "Z",
        "0!a@1#b$2%c^3&D*4(E)5-F_",
        ""
    };
    double startTs = GetNowTs();
    string wlog, rlog;
    for (int i = 0; data[i].size() > 0; i++) {
        ASSERT_EQ(system(("hostacm_moduletest -SDK -asyncWrite '" + data[i] + "'").c_str()), 0);
        wlog = "send data[" + data[i] + "] to device";
        rlog = "recv data[" + data[i] + "] from device";
        sleep(2);
        EXPECT_TRUE(HasLog(wlog, startTs, WLOG_FILE));
        EXPECT_TRUE(HasLog(rlog, startTs, RLOG_FILE));
    }
    printf("------end UsbHostSerialIOTest_002------\n");
}

/**
 * @tc.number    : ping
 * @tc.name      : 验证复合设备网卡功能
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostComposeDeviceFuncTest, UsbHostPing_001, TestSize.Level1)
{
    printf("------start UsbHostPing_001------\n");
    EXPECT_EQ(system("host_level_ip -c 5 10.0.0.4"), 0);
    printf("------end UsbHostPing_001------\n");
}

/**
 * @tc.number    : ping
 * @tc.name      : 验证发送不同大小字节ping网卡是否有异常
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostComposeDeviceFuncTest, UsbHostPing_002, TestSize.Level1)
{
    printf("------start UsbHostPing_002------\n");
    EXPECT_EQ(system("host_level_ip -s 8 -c 3 10.0.0.4"), 0);
    EXPECT_EQ(system("host_level_ip -s 100 -c 3 10.0.0.4"), 0);
    EXPECT_EQ(system("host_level_ip -s 400 -c 3 10.0.0.4"), 0);
    printf("------end UsbHostPing_002------\n");
}


/**
 * @tc.number    : ping & io
 * @tc.name      : ping网卡的同时读写数据
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostComposeDeviceFuncTest, UsbHostSerialIoWithPing_001, TestSize.Level1)
{
    printf("------start UsbHostSerialIoWithPing_001------\n");
    ASSERT_EQ(system("host_level_ip -c 5 10.0.0.4 &"), 0);
    sleep(2);
    const string data = "abc123";
    double startTs = GetNowTs();
    string wlog, rlog;
    ASSERT_EQ(system(("hostacm_moduletest -SDK -asyncWrite '" + data + "'").c_str()), 0);
    wlog = "send data[" + data + "] to device";
    rlog = "recv data[" + data + "] from device";
    EXPECT_TRUE(HasLog(wlog, startTs, WLOG_FILE));
    sleep(1);
    EXPECT_TRUE(HasLog(rlog, startTs, RLOG_FILE));
    ASSERT_EQ(system("killall hostacm_moduletest"), 0) << "ErrInfo:  failed to kill hostacm_moduletest";
    printf("------end UsbHostSerialIoWithPing_001------\n");
}
}