/*
 * UsbHostRawApiFuncTest.cpp
 *
 * usb serial device function test source file
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
#include "securec.h"
extern "C" {
#include "usbhost_ddk_test.h"
}

using namespace std;
using namespace testing::ext;

namespace {

const int TEST_COUNT = 3;


class UsbHostRawApiFuncTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void UsbHostRawApiFuncTest::SetUpTestCase(){
    printf("------start UsbHostRawApiFuncTest------\n");
    const char *apiType = "-RAW";
    UsbHostDdkTestInit(const_cast<char*>(apiType));
}

void UsbHostRawApiFuncTest::TearDownTestCase(){
    char writeBuf[] = "q";
    UsbHostDdkTestOpen(HOST_ACM_ASYNC_WRITE);
    UsbHostDdkTestAsyncWrite(writeBuf);
    UsbHostDdkTestClose(HOST_ACM_ASYNC_WRITE);
    TestExit();
    printf("------end UsbHostRawApiFuncTest------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IOread_write_001，H_Lx_H_Sub_usb_IOread_write_003
 * @tc.name      : USB串口同步数据读写
 * @tc.size      : MEDIUM
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostRawApiFuncTest, UsbSerialReadSync_001, TestSize.Level1)
{
    printf("------start UsbSerialReadSync_001------\n");
    char writeBuf[256] = "abc";
    char readBuf[256] = {0};
    UsbHostDdkTestOpen(HOST_ACM_SYNC_WRITE);
    UsbHostDdkTestSyncWrite(writeBuf);
    UsbHostDdkTestClose(HOST_ACM_SYNC_WRITE);
    UsbHostDdkTestOpen(HOST_ACM_SYNC_READ);
    UsbHostDdkTestSyncRead(readBuf);
    UsbHostDdkTestClose(HOST_ACM_SYNC_READ);
    EXPECT_EQ(strcmp(writeBuf, readBuf), 0);
    printf("------end UsbSerialReadSync_001------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IOread_write_001，H_Lx_H_Sub_usb_IOread_write_006
 * @tc.name      : USB串口同步读+异步写
 * @tc.size      : MEDIUM
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostRawApiFuncTest, UsbSerialReadSync_002, TestSize.Level1)
{
    printf("------start UsbSerialReadSync_002------\n");
    char writeBuf[256] = "abc";
    char readBuf[256] = {0};
    UsbHostDdkTestOpen(HOST_ACM_ASYNC_WRITE);
    UsbHostDdkTestAsyncWrite(writeBuf);
    UsbHostDdkTestClose(HOST_ACM_ASYNC_WRITE);
    UsbHostDdkTestOpen(HOST_ACM_SYNC_READ);
    UsbHostDdkTestSyncRead(readBuf);
    UsbHostDdkTestClose(HOST_ACM_SYNC_READ);
    EXPECT_EQ(strcmp(writeBuf, readBuf), 0);
    printf("------end UsbSerialReadSync_002------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IOread_write_001，H_Lx_H_Sub_usb_IOread_write_003
 * @tc.name      : USB串口同步数据读写
 * @tc.size      : MEDIUM
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostRawApiFuncTest, UsbSerialReadSync_003, TestSize.Level1)
{
    printf("------start UsbSerialReadSync_003------\n");
    const char *data[] = {
        "0123456789",
        "Z",
        "0!a@1#b$2%c^3&D*4(E)5-F_",
        ""
    };
    char readBuf[256] = {0};
    for (int i = 0; strlen(data[i]) > 0 > 0; i++) {
        memset(readBuf, 0, sizeof(readBuf));
        UsbHostDdkTestOpen(HOST_ACM_SYNC_WRITE);
        UsbHostDdkTestSyncWrite(const_cast<char *>(data[i]));
        UsbHostDdkTestClose(HOST_ACM_SYNC_WRITE);
        UsbHostDdkTestOpen(HOST_ACM_SYNC_READ);
        UsbHostDdkTestSyncRead(readBuf);
        UsbHostDdkTestClose(HOST_ACM_SYNC_READ);
        EXPECT_EQ(strcmp(const_cast<char *>(data[i]), readBuf), 0);
    }
    printf("------end UsbSerialReadSync_003------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IOread_write_001，H_Lx_H_Sub_usb_IOread_write_006
 * @tc.name      : USB串口同步读+异步写
 * @tc.size      : MEDIUM
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostRawApiFuncTest, UsbSerialReadSync_004, TestSize.Level1)
{
    printf("------start UsbSerialReadSync_004------\n");
    const char *data[] = {
        "0123456789",
        "Z",
        "0!a@1#b$2%c^3&D*4(E)5-F_",
        ""
    };
    char readBuf[256] = {0};
    for (int i = 0; strlen(data[i]) > 0 > 0; i++) {
        memset(readBuf, 0, sizeof(readBuf));
        UsbHostDdkTestOpen(HOST_ACM_ASYNC_WRITE);
        UsbHostDdkTestAsyncWrite(const_cast<char *>(data[i]));
        UsbHostDdkTestClose(HOST_ACM_ASYNC_WRITE);
        UsbHostDdkTestOpen(HOST_ACM_SYNC_READ);
        UsbHostDdkTestSyncRead(readBuf);
        UsbHostDdkTestClose(HOST_ACM_SYNC_READ);
        EXPECT_EQ(strcmp(const_cast<char *>(data[i]), readBuf), 0);
    }
    printf("------end UsbSerialReadSync_004------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IOread_write_001，H_Lx_H_Sub_usb_IOread_write_003
 * @tc.name      : USB串口同步读写1KB数据
 * @tc.size      : MEDIUM
 * @tc.type      : FUNC
 * @tc.level     : Level 2
 */
HWTEST_F(UsbHostRawApiFuncTest, UsbSerialReadSync_005, TestSize.Level2)
{
    printf("------start UsbSerialReadSync_005------\n");
    const string s = "0123456789abcdef";
    string data;
    int totalSize = 1024;
    int writeCnt = 8;
    unsigned int n = 0;
    while (n < totalSize / writeCnt / s.size()) {
        data += s;
        n++;
    }
    char readBuf[256] = {0};
    char writeBuf[256] = {0};
    strcpy(writeBuf, data.c_str());
    for (int i = 0; i < writeCnt; i++) {
        memset(readBuf, 0, sizeof(readBuf));
        UsbHostDdkTestOpen(HOST_ACM_SYNC_WRITE);
        UsbHostDdkTestSyncWrite(writeBuf);
        UsbHostDdkTestClose(HOST_ACM_SYNC_WRITE);
        UsbHostDdkTestOpen(HOST_ACM_SYNC_READ);
        UsbHostDdkTestSyncRead(readBuf);
        UsbHostDdkTestClose(HOST_ACM_SYNC_READ);
        EXPECT_EQ(strcmp(writeBuf, readBuf), 0);
    }
    printf("------end UsbSerialReadSync_005------\n");
}

static void TestAsyncRead(char *readBuf, int timeout)
{
    printf("------TestAsyncRead start-----");
    if (strlen(readBuf) > 0) {
        memset(readBuf, 0, sizeof(readBuf));
    }
    timeout = timeout * 1000;
    UsbHostDdkTestOpen(HOST_ACM_ASYNC_READ);
    while(timeout-- > 0) {
        UsbHostDdkTestAsyncRead(readBuf);
        if (strlen(readBuf) > 0){
            break;
        }
        usleep(1000);
    }
    printf("------TestAsyncRead end-----");
}


/**
 * @tc.number    : H_Lx_H_Sub_usb_IOread_write_005， H_Lx_H_Sub_usb_IOread_write_006
 * @tc.name      : USB串口异步数据读写
 * @tc.size      : MEDIUM
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostRawApiFuncTest, UsbSerialReadAsync_001, TestSize.Level1)
{
    printf("------start UsbSerialReadAsync_001------\n");
    char writeBuf[256] = "abc";
    char readBuf[256] = {0};
    UsbHostDdkTestOpen(HOST_ACM_ASYNC_WRITE);
    UsbHostDdkTestAsyncWrite(writeBuf);
    UsbHostDdkTestClose(HOST_ACM_ASYNC_WRITE);
    TestAsyncRead(readBuf, 5);
    EXPECT_EQ(strcmp(writeBuf, readBuf), 0);
    printf("------end UsbSerialReadAsync_001------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IOread_write_005， H_Lx_H_Sub_usb_IOread_write_003
 * @tc.name      : USB串口异步读+同步写
 * @tc.size      : MEDIUM
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostRawApiFuncTest, UsbSerialReadAsync_002, TestSize.Level1)
{
    printf("------start UsbSerialReadAsync_002------\n");
    char writeBuf[256] = "abc";
    char readBuf[256] = {0};
    UsbHostDdkTestOpen(HOST_ACM_SYNC_WRITE);
    UsbHostDdkTestSyncWrite(writeBuf);
    UsbHostDdkTestClose(HOST_ACM_SYNC_WRITE);
    TestAsyncRead(readBuf, 5);
    EXPECT_EQ(strcmp(writeBuf, readBuf), 0);
    printf("------end UsbSerialReadAsync_002------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IOread_write_005， H_Lx_H_Sub_usb_IOread_write_006
 * @tc.name      : USB串口异步数据读写
 * @tc.size      : MEDIUM
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostRawApiFuncTest, UsbSerialReadAsync_003, TestSize.Level1)
{
    printf("------start UsbSerialReadAsync_003------\n");
    const char *data[] = {
        "0123456789",
        "Z",
        "0!a@1#b$2%c^3&D*4(E)5-F_",
        ""
    };
    char readBuf[256] = {0};
    for (int i = 0; strlen(data[i]) > 0; i++) {
        memset(readBuf, 0, sizeof(readBuf));
        UsbHostDdkTestOpen(HOST_ACM_ASYNC_WRITE);
        UsbHostDdkTestAsyncWrite(const_cast<char *>(data[i]));
        UsbHostDdkTestClose(HOST_ACM_ASYNC_WRITE);
        TestAsyncRead(readBuf, 5);
        EXPECT_EQ(strcmp(const_cast<char *>(data[i]), readBuf), 0);
    }
    printf("------end UsbSerialReadAsync_003------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IOread_write_005， H_Lx_H_Sub_usb_IOread_write_003
 * @tc.name      : USB串口异步读+同步写
 * @tc.size      : MEDIUM
 * @tc.type      : FUNC
 * @tc.level     : Level 1
 */
HWTEST_F(UsbHostRawApiFuncTest, UsbSerialReadAsync_004, TestSize.Level1)
{
    printf("------start UsbSerialReadAsync_004------\n");
    const char *data[] = {
        "0123456789",
        "Z",
        "0!a@1#b$2%c^3&D*4(E)5-F_",
        ""
    };
    char readBuf[256] = {0};
    for (int i = 0; strlen(data[i]) > 0; i++) {
        memset(readBuf, 0, sizeof(readBuf));
        UsbHostDdkTestOpen(HOST_ACM_SYNC_WRITE);
        UsbHostDdkTestSyncWrite(const_cast<char *>(data[i]));
        UsbHostDdkTestClose(HOST_ACM_SYNC_WRITE);
        TestAsyncRead(readBuf, 5);
        EXPECT_EQ(strcmp(const_cast<char *>(data[i]), readBuf), 0);
    }
    printf("------end UsbSerialReadAsync_004------\n");
}

/**
 * @tc.number    : H_Lx_H_Sub_usb_IOread_write_005， H_Lx_H_Sub_usb_IOread_write_006
 * @tc.name      : USB串口异步读写1KB数据
 * @tc.size      : MEDIUM
 * @tc.type      : FUNC
 * @tc.level     : Level 2
 */
HWTEST_F(UsbHostRawApiFuncTest, UsbSerialReadAsync_005, TestSize.Level2)
{
    printf("------start UsbSerialReadAsync_005------\n");
    const string s = "0123456789abcdef";
    string data;
    int totalSize = 1024;
    int writeCnt = 8;
    unsigned int n = 0;
    while (n < totalSize / writeCnt / s.size()) {
        data += s;
        n++;
    }
    char readBuf[256] = {0};
    char writeBuf[256] = {0};
    strcpy(writeBuf, data.c_str());
    for (int i = 0; i < writeCnt; i++) {
        memset(readBuf, 0, sizeof(readBuf));
        UsbHostDdkTestOpen(HOST_ACM_ASYNC_WRITE);
        UsbHostDdkTestAsyncWrite(writeBuf);
        UsbHostDdkTestClose(HOST_ACM_ASYNC_WRITE);
        TestAsyncRead(readBuf, 5);
        EXPECT_EQ(strcmp(writeBuf, readBuf), 0);
    }
    printf("------end UsbSerialReadAsync_005------\n");
}
}