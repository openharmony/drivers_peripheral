/*
 * UsbDeviceComposeFuncTest.cpp
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

class UsbDeviceComposeFuncTest : public testing::Test {
protected:
    static void SetUpTestCase(void)
    {
        printf("------start UsbDeviceComposeFuncTest------\n");
        system("cat /dev/null > /data/acm_write_xts");
        system("cat /dev/null > /data/acm_read_xts");
    }
    static void TearDownTestCase(void)
    {
        printf("------end UsbDeviceComposeFuncTest------\n");
    }
};

/**
 * @tc.number    : H_Lx_H_Sub_usb_IO read_002，H_Lx_H_Sub_usb_IO read_008
 * @tc.name      : 验证device sdk的数据读写
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbDeviceComposeFuncTest, UsbSerialIOTest_001, TestSize.Level1)
{
    printf("------start UsbSerialIOTest_001------\n");
    ASSERT_EQ(system("acm_read &"), 0) << "ErrInfo:  failed to start acm_read";
    const string data = "abc123";
    double startTs = GetNowTs();
    string wlog, rlog;
    ASSERT_EQ(system(("acm_write '" + data + "'").c_str()), 0);
    wlog = "send data[" + data + "] to host";
    rlog = "recv data[" + data + "] from host";
    sleep(2);
    EXPECT_TRUE(HasLog(wlog, startTs, WLOG_FILE));
    EXPECT_TRUE(HasLog(rlog, startTs, RLOG_FILE));
    printf("------end UsbSerialIOTest_001------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IO read_002，H_Lx_H_Sub_usb_IO read_008
 * @tc.name      : 验证device sdk的数据读写
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbDeviceComposeFuncTest, UsbSerialIOTest_002, TestSize.Level1)
{
    printf("------start UsbSerialIOTest_002------\n");
    const string data[] = {
        "0123456789",
        "Z",
        "0!a@1#b$2%c^3&D*4(E)5-F_",
        ""
    };
    double startTs = GetNowTs();
    string wlog, rlog;
    for (int i = 0; data[i].size() > 0; i++) {
        ASSERT_EQ(system(("acm_write '" + data[i] + "'").c_str()), 0);
        wlog = "send data[" + data[i] + "] to host";
        rlog = "recv data[" + data[i] + "] from host";
        sleep(2);
        EXPECT_TRUE(HasLog(wlog, startTs, WLOG_FILE));
        EXPECT_TRUE(HasLog(rlog, startTs, RLOG_FILE));
    }
    ASSERT_EQ(system("killall acm_read"), 0) << "ErrInfo:  failed to kill acm_read";
    printf("------end UsbSerialIOTest_002------\n");
}

/**
 * @tc.number    : ping
 * @tc.name      : 验证能否ping通网卡
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbDeviceComposeFuncTest, UsbNetPing_001, TestSize.Level1)
{
    printf("------start UsbNetPing_001------\n");
    EXPECT_EQ(system("level_ip -c 5 10.0.0.10"), 0);
    printf("------end UsbNetPing_001------\n");
}

/**
 * @tc.number    : ping
 * @tc.name      : 验证发送不同大小字节ping网卡是否有异常
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbDeviceComposeFuncTest, UsbNetPing_002, TestSize.Level1)
{
    printf("------start UsbNetPing_002------\n");
    EXPECT_EQ(system("level_ip -s 8 -c 3 10.0.0.10"), 0);
    EXPECT_EQ(system("level_ip -s 100 -c 3 10.0.0.10"), 0);
    EXPECT_EQ(system("level_ip -s 400 -c 3 10.0.0.10"), 0);
    printf("------end UsbNetPing_002------\n");
}


/**
 * @tc.number    : ping & io
 * @tc.name      : ping网卡的同时读写数据
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbDeviceComposeFuncTest, UsbSerialIoWithNetPing_001, TestSize.Level1)
{
    printf("------start UsbSerialIoWithNetPing_001------\n");
    ASSERT_EQ(system("level_ip -c 5 10.0.0.10 &"), 0);
    sleep(2);
    ASSERT_EQ(system("acm_read &"), 0) << "ErrInfo:  failed to start acm_read";
    const string data = "abc123";
    double startTs = GetNowTs();
    string wlog, rlog;
    ASSERT_EQ(system(("acm_write '" + data + "'").c_str()), 0);
    wlog = "send data[" + data + "] to host";
    rlog = "recv data[" + data + "] from host";
    EXPECT_TRUE(HasLog(wlog, startTs, WLOG_FILE));
    sleep(1);
    EXPECT_TRUE(HasLog(rlog, startTs, RLOG_FILE));
    ASSERT_EQ(system("killall acm_read"), 0) << "ErrInfo:  failed to kill acm_read";
    printf("------end UsbSerialIoWithNetPing_001------\n");
}
}