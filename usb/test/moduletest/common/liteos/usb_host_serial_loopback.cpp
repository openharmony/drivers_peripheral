/*
 * UsbSerialDeviceFuncTest.cpp
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
class UsbHostSerialLoopback : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void UsbHostSerialLoopback::SetUpTestCase(){
    const char *apiType = "-SDK";
    UsbHostDdkTestInit(const_cast<char*>(apiType));
}

void UsbHostSerialLoopback::TearDownTestCase(){
    TestExit();
}

HWTEST_F(UsbHostSerialLoopback, HostSerialLoopback, TestSize.Level1)
{
    printf("------start HostSerialLoopback------\n");
    char data[256] = {0};
    for ( ; ; ) {
        UsbHostDdkTestOpen(HOST_ACM_SYNC_READ);
        UsbHostDdkTestSyncRead(data);
        UsbHostDdkTestClose(HOST_ACM_SYNC_READ);
        if (strlen(data) > 0) {
            if (strcmp(data, "q") == 0) {
                break;
            }
            UsbHostDdkTestOpen(HOST_ACM_SYNC_WRITE);
            UsbHostDdkTestSyncWrite(data);
            UsbHostDdkTestClose(HOST_ACM_SYNC_WRITE);
            memset(data, 0, sizeof(data));
        }
    }
    printf("------end HostSerialLoopback------\n");
}

}