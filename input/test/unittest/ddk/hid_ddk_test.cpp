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

#include <gtest/gtest.h>
#include <hdf_log.h>
#include <linux/uinput.h>
#include "v1_0/ihid_ddk.h"
#include "accesstoken_kit.h"

using namespace OHOS::HDI::Input::Ddk::V1_0;
using namespace testing::ext;

namespace {
    sptr<IHidDdk> g_hidDdk = nullptr;
}

class HidDdkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override {};
    void TearDown() override {};
};

void HidDdkTest::SetUpTestCase()
{
    g_hidDdk = IHidDdk::Get();
}

void HidDdkTest::TearDownTestCase()
{
    g_hidDdk = nullptr;
}

HWTEST_F(HidDdkTest, CheckIHidDdkGet001, TestSize.Level1)
{
    ASSERT_NE(g_hidDdk, nullptr);
}

HWTEST_F(HidDdkTest, CreateDevice001, TestSize.Level1)
{
    struct Hid_Device hidDevice = {
        .deviceName = "VSoC keyboard",
        .vendorId = 0x6006,
        .productId = 0x6008,
        .version = 1,
        .bustype = BUS_USB
    };

    struct Hid_EventProperties hidEventProp = {
        .hidEventTypes = {HID_EV_KEY},
        .hidKeys = {HID_KEY_1, HID_KEY_SPACE, HID_KEY_BACKSPACE, HID_KEY_ENTER}
    };

    uint32_t deviceId = 0;
    int32_t ret = g_hidDdk->CreateDevice(hidDevice, hidEventProp, deviceId);
    ASSERT_EQ(ret, 0);
}

HWTEST_F(HidDdkTest, EmitEvent001, TestSize.Level1)
{
    struct Hid_Device hidDevice = {
        .deviceName = "VSoC keyboard",
        .vendorId = 0x6006,
        .productId = 0x6008,
        .version = 1,
        .bustype = BUS_USB
    };

    struct Hid_EventProperties hidEventProp = {
        .hidEventTypes = {HID_EV_KEY},
        .hidKeys = {HID_KEY_1, HID_KEY_SPACE, HID_KEY_BACKSPACE, HID_KEY_ENTER}
    };

    uint32_t deviceId = 0;
    int32_t ret = g_hidDdk->CreateDevice(hidDevice, hidEventProp, deviceId);
    ASSERT_EQ(ret, 0);

    std::vector<struct Hid_EmitItem> items = {
        {1, 0x14a, 108},
        {3, 0,     50 },
        {3, 1,     50 }
    };

    ret = g_hidDdk->EmitEvent(deviceId, items);
    ASSERT_EQ(ret, 0);
}

HWTEST_F(HidDdkTest, EmitEvent002, TestSize.Level1)
{
    std::vector<struct Hid_EmitItem> items = {
        {1, 0x14a, 108},
        {3, 0,     50 },
        {3, 1,     50 }
    };
    uint32_t deviceId = -1;
    int32_t ret = g_hidDdk->EmitEvent(deviceId, items);
    ASSERT_NE(ret, 0);
}

HWTEST_F(HidDdkTest, DestroyDevice001, TestSize.Level1)
{
    struct Hid_Device hidDevice = {
        .deviceName = "VSoC keyboard",
        .vendorId = 0x6006,
        .productId = 0x6008,
        .version = 1,
        .bustype = BUS_USB
    };

    struct Hid_EventProperties hidEventProp = {
        .hidEventTypes = {HID_EV_KEY},
        .hidKeys = {HID_KEY_1, HID_KEY_SPACE, HID_KEY_BACKSPACE, HID_KEY_ENTER}
    };

    uint32_t deviceId = 0;
    int32_t ret = g_hidDdk->CreateDevice(hidDevice, hidEventProp, deviceId);
    ASSERT_EQ(ret, 0);
 
    ret = g_hidDdk->DestroyDevice(deviceId);
    ASSERT_EQ(ret, 0);
}

HWTEST_F(HidDdkTest, DestroyDevice002, TestSize.Level1)
{
    uint32_t deviceId = -1;
    int32_t ret = g_hidDdk->DestroyDevice(deviceId);
    ASSERT_NE(ret, 0);
}
