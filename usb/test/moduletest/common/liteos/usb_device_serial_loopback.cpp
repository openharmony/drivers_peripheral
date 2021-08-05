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
#include "lib_acm_test.h"
}

using namespace std;
using namespace testing::ext;

namespace {

class UsbDeviceSerialLoopback : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void UsbDeviceSerialLoopback::SetUpTestCase(){
    acm_open();
}

void UsbDeviceSerialLoopback::TearDownTestCase(){
    acm_close();
}

HWTEST_F(UsbDeviceSerialLoopback, DeviceSerialLoopback, TestSize.Level1)
{
    printf("------start DeviceSerialLoopback------\n");
    char data[256] = {0};
    for ( ; ; ) {
        acm_read(data);
        if (strlen(data) > 0) {
            if (strcmp(data, "q") == 0) {
                break;
            }
            acm_write(data);
            memset(data, 0, sizeof(data));
        }
    }
    printf("------end DeviceSerialLoopback------\n");
}
}