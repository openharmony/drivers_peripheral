/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hdf_wifi_test.h"
#include <gtest/gtest.h>
#include "hdf_uhdf_test.h"
#include "wifi_driver_client.h"

using namespace testing::ext;

namespace ClientTest {
static struct HdfDevEventlistener g_devEventListener;
static struct HdfDevEventlistener g_devEventListener1;
static struct HdfDevEventlistener g_devEventListener2;

class WifiClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() const;
    void TearDown() const;
};

void WifiClientTest::SetUpTestCase() {}

void WifiClientTest::TearDownTestCase() {}

void WifiClientTest::SetUp() const {}

void WifiClientTest::TearDown() const {}

static int OnWifiEventListener(struct HdfDevEventlistener *listener,
    struct HdfIoService *service, uint32_t id, struct HdfSBuf *data)
{
    (void)listener;
    (void)service;
    (void)id;
    if (data == NULL) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @tc.name: WifiClientInitAndDeinit001
 * @tc.desc: In normal cases, the WLAN client is initialized and deinitialized once.
 * @tc.type: FUNC
 * @tc.require: AR000F869F, AR000F8QNL
 */
HWTEST_F(WifiClientTest, WifiClientInitAndDeinit001, TestSize.Level0)
{
    int ret;

    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);
    WifiMsgServiceDeinit();
}

/**
 * @tc.name: WifiClientInitAndDeinit002
 * @tc.desc: In normal cases, the WLAN client is initialized and deinitialized for multiple times.
 * @tc.type: FUNC
 * @tc.require: AR000F869F, AR000F8QNL
 */
HWTEST_F(WifiClientTest, WifiClientInitAndDeinit002, TestSize.Level0)
{
    int ret;

    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);
    WifiMsgServiceDeinit();

    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);
    WifiMsgServiceDeinit();
}

/**
 * @tc.name: WifiClientInitAndDeinit003
 * @tc.desc: Initialize the WLAN client for multiple times.
 * @tc.type: FUNC
 * @tc.require: AR000F869F, AR000F8QNL
 */
HWTEST_F(WifiClientTest, WifiClientInitAndDeinit003, TestSize.Level0)
{
    int ret;

    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);
    WifiMsgServiceDeinit();
}

/**
 * @tc.name: WifiRegisterListener001
 * @tc.desc: Single registration and unregistration of the listener in normal cases.
 * @tc.type: FUNC
 * @tc.require: AR000F869F, AR000F8QNL
 */
HWTEST_F(WifiClientTest, WifiRegisterListener001, TestSize.Level0)
{
    int ret;

    g_devEventListener.onReceive = OnWifiEventListener;
    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WifiMsgRegisterEventListener(&g_devEventListener);
    EXPECT_EQ(HDF_SUCCESS, ret);
    WifiMsgUnregisterEventListener(&g_devEventListener);
    WifiMsgServiceDeinit();
}

/**
 * @tc.name: WifiRegisterListener002
 * @tc.desc: Multiple registrations and unregistrations of the listener in normal cases.
 * @tc.type: FUNC
 * @tc.require: AR000F869F, AR000F8QNL
 */
HWTEST_F(WifiClientTest, WifiRegisterListener002, TestSize.Level0)
{
    int ret;

    g_devEventListener.onReceive = OnWifiEventListener;
    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = WifiMsgRegisterEventListener(&g_devEventListener);
    EXPECT_EQ(HDF_SUCCESS, ret);
    WifiMsgUnregisterEventListener(&g_devEventListener);
    ret = WifiMsgRegisterEventListener(&g_devEventListener);
    EXPECT_EQ(HDF_SUCCESS, ret);
    WifiMsgUnregisterEventListener(&g_devEventListener);

    WifiMsgServiceDeinit();
}

/**
 * @tc.name: WifiRegisterListener003
 * @tc.desc: In normal cases, multiple listeners are registered and deregistered.
 * @tc.type: FUNC
 * @tc.require: AR000F869F
 */
HWTEST_F(WifiClientTest, WifiRegisterListener003, TestSize.Level0)
{
    int ret;

    g_devEventListener1.onReceive = OnWifiEventListener;
    g_devEventListener2.onReceive = OnWifiEventListener;
    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = WifiMsgRegisterEventListener(&g_devEventListener1);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WifiMsgRegisterEventListener(&g_devEventListener2);
    EXPECT_EQ(HDF_SUCCESS, ret);
    WifiMsgUnregisterEventListener(&g_devEventListener1);
    WifiMsgUnregisterEventListener(&g_devEventListener2);

    WifiMsgServiceDeinit();
}

/**
 * @tc.name: WifiRegisterListener004
 * @tc.desc: Repeatedly registering a listener.
 * @tc.type: FUNC
 * @tc.require: AR000F869F
 */
HWTEST_F(WifiClientTest, WifiRegisterListener004, TestSize.Level0)
{
    int ret;

    g_devEventListener.onReceive = OnWifiEventListener;
    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = WifiMsgRegisterEventListener(&g_devEventListener);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WifiMsgRegisterEventListener(&g_devEventListener);
    EXPECT_NE(HDF_SUCCESS, ret);
    WifiMsgUnregisterEventListener(&g_devEventListener);

    WifiMsgServiceDeinit();
}

/**
 * @tc.name: WifiRegisterListener005
 * @tc.desc: Registration and unregistration of interception in abnormal cases.
 * @tc.type: FUNC
 * @tc.require: AR000F869F
 */
HWTEST_F(WifiClientTest, WifiRegisterListener005, TestSize.Level0)
{
    int ret;

    g_devEventListener.onReceive = NULL;
    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WifiMsgRegisterEventListener(&g_devEventListener);
    EXPECT_NE(HDF_SUCCESS, ret);
    WifiMsgServiceDeinit();
}

/**
 * @tc.name: WifiRegisterListener006
 * @tc.desc: Deinitialization when the listener is not completely unregistered.
 * @tc.type: FUNC
 * @tc.require: AR000F869F
 */
HWTEST_F(WifiClientTest, WifiRegisterListener006, TestSize.Level0)
{
    int ret;

    g_devEventListener1.onReceive = OnWifiEventListener;
    g_devEventListener2.onReceive = OnWifiEventListener;
    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = WifiMsgRegisterEventListener(&g_devEventListener1);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = WifiMsgRegisterEventListener(&g_devEventListener2);
    EXPECT_EQ(HDF_SUCCESS, ret);
    WifiMsgUnregisterEventListener(&g_devEventListener1);
    WifiMsgServiceDeinit();
    WifiMsgUnregisterEventListener(&g_devEventListener2);
    WifiMsgServiceDeinit();
}

/**
 * @tc.name: WifiRegisterListener007
 * @tc.desc: Canceling a listener when no listener is registered.
 * @tc.type: FUNC
 * @tc.require: AR000F869F
 */
HWTEST_F(WifiClientTest, WifiRegisterListener007, TestSize.Level0)
{
    int ret;

    g_devEventListener.onReceive = OnWifiEventListener;
    ret = WifiMsgServiceInit();
    EXPECT_EQ(HDF_SUCCESS, ret);

    WifiMsgUnregisterEventListener(&g_devEventListener);
    ret = WifiMsgRegisterEventListener(&g_devEventListener);
    EXPECT_EQ(HDF_SUCCESS, ret);
    WifiMsgUnregisterEventListener(&g_devEventListener);

    WifiMsgServiceDeinit();
}
};
