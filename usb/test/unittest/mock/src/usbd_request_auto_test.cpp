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

#include <climits>
#include <iostream>
#include <vector>

#include "mock_linux_adapter.h"
#include "usb_impl.h"
#include "usbd_dispatcher.h"
#include "UsbSubscriberTest.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/iusbd_bulk_callback.h"
#include "v1_0/usb_types.h"

using ::testing::Exactly;
using ::testing::Return;

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;

constexpr uint8_t INDEX_0 = 0;
constexpr uint8_t INDEX_1 = 1;
constexpr uint8_t INDEX_INVALID = 255;
constexpr uint8_t CONFIG_ID_0 = 0;
constexpr uint8_t CONFIG_ID_INVALID = 222;
constexpr uint8_t BUS_NUM_INVALID = 255;
constexpr uint8_t DEV_ADDR_INVALID = 255;
constexpr uint8_t STRING_ID_INVALID = 233;
constexpr uint32_t MAX_BUFFER_LENGTH = 256;
constexpr uint32_t TAG_NUM_10 = 10;
constexpr uint8_t INTERFACEID_OK = 1;
constexpr uint8_t INTERFACEID_INVALID = 255;
constexpr uint8_t POINTID_INVALID = 158;
// data interface have 2 point : 1->bulk_out 2->bulk_in
constexpr uint8_t POINTID_DIR_IN = USB_ENDPOINT_DIR_IN | 2;
constexpr uint8_t POINTID_DIR_OUT = USB_ENDPOINT_DIR_OUT | 1;
constexpr uint8_t BUS_NUM_OK = 6;
constexpr uint8_t DEV_ADDR_OK = 2;
constexpr uint8_t INVALID_NUM = 222;
constexpr uint32_t TIME_WAIT = 10000;

namespace {
class UsbdRequestTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static UsbDev dev_;
};
class UsbdBulkCallbackTest : public OHOS::HDI::Usb::V1_0::IUsbdBulkCallback {
public:
    UsbdBulkCallbackTest() = default;
    ~UsbdBulkCallbackTest() = default;
    int32_t OnBulkWriteCallback(int32_t status, int32_t actLength) override
    {
        return 0;
    };
    int32_t OnBulkReadCallback(int32_t status, int32_t actLength) override
    {
        return 0;
    };
};
sptr<IUsbInterface> g_usbInterface = nullptr;
UsbDev UsbdRequestTest::dev_ = {0, 0};

void UsbdRequestTest::SetUpTestCase(void)
{
    struct UsbOsAdapterOps *osAdapterOps = UsbAdapterGetOps();
    g_usbInterface = IUsbInterface::Get(true);
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        exit(0);
    }
    sptr<UsbImpl> sp = static_cast<UsbImpl *>(g_usbInterface.GetRefPtr());
    osAdapterOps->openDevice = FuncAdapterOpenDevice;
    osAdapterOps->init = FuncAdapterInit;
    osAdapterOps->getConfiguration = FuncAdapterGetConfiguration;
    osAdapterOps->getConfigDescriptor = FuncAdapterGetConfigDescriptor;
    osAdapterOps->urbCompleteHandle = FuncAdapterUrbCompleteHandle;
    osAdapterOps->allocRequest = FuncAdapterAllocRequest;
    osAdapterOps->cancelRequest = FuncAdapterCancelRequest;
    osAdapterOps->submitRequest = FuncAdapterSubmitRequest;
    osAdapterOps->claimInterface = FuncAdapterClaimInterface;
    osAdapterOps->detachKernelDriverAndClaim = FuncAdapterClaimInterface;
    osAdapterOps->freeRequest = FuncAdapterFreeRequest;
    osAdapterOps->closeDevice = FuncAdapterCloseDevice;
    osAdapterOps->setConfiguration = FuncAdapterSetConfiguration;
    osAdapterOps->releaseInterface = FuncAdapterReleaseInterface;
    auto ret = UsbdDispatcher::UsbdDeviceCreateAndAttach(sp, BUS_NUM_OK, DEV_ADDR_OK);
    ASSERT_EQ(0, ret);
    dev_ = {BUS_NUM_OK, DEV_ADDR_OK};
    ret = g_usbInterface->OpenDevice(dev_);
    ASSERT_EQ(0, ret);
}

void UsbdRequestTest::TearDownTestCase(void)
{
    g_usbInterface->CloseDevice(dev_);
    sptr<UsbImpl> sp = static_cast<UsbImpl *>(g_usbInterface.GetRefPtr());
    UsbdDispatcher::UsbdDeviceDettach(sp, BUS_NUM_OK, DEV_ADDR_OK);
}

/**
 * @tc.name: UsbdConfig001
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig001, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->SetConfig(dev, configIndex);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdConfig002
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig002, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbInterface->SetConfig(dev, configIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig003
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig003, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->SetConfig(dev, configIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig004
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, configIndex error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig004, TestSize.Level1)
{
    uint8_t configIndex = INDEX_INVALID;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->SetConfig(dev, configIndex);
    ASSERT_NE(ret, 0);
    configIndex = INDEX_1;
    ret = g_usbInterface->SetConfig(dev, configIndex);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdConfig005
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig005, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->SetConfig(dev, configIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig006
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, busNum && configIndex error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig006, TestSize.Level1)
{
    uint8_t configIndex = INDEX_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbInterface->SetConfig(dev, configIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig007
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, devAddr && configIndex error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig007, TestSize.Level1)
{
    uint8_t configIndex = INDEX_INVALID;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->SetConfig(dev, configIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig008
 * @tc.desc: Test functions to SetConfig
 * @tc.desc: int32_t SetConfig(const UsbDev &dev, uint8_t configIndex);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && configIndex error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetConfig008, TestSize.Level1)
{
    uint8_t configIndex = INDEX_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->SetConfig(dev, configIndex);
    ASSERT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdConfig001
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfig001, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->GetConfig(dev, configIndex);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdConfig002
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfig002, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbInterface->GetConfig(dev, configIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig003
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfig003, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->GetConfig(dev, configIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdConfig004
 * @tc.desc: Test functions to GetConfig
 * @tc.desc: int32_t GetConfig(const UsbDev &dev, uint8_t &configIndex);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfig004, TestSize.Level1)
{
    uint8_t configIndex = INDEX_1;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->GetConfig(dev, configIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface001
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface001, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdClaimInterface002
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface002, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface003
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface003, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface004
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface004, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    interfaceId = INTERFACEID_INVALID;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface005
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface005, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface006
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface006, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface007
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface007, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface008
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface008, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface009
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface009, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 0);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdClaimInterface010
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface010, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    dev.busNum = BUS_NUM_INVALID;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 0);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdClaimInterface011
 * @tc.desc: Test functions to ClaimInterface
 * @tc.desc: int32_t  ClaimInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdClaimInterface011, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 0);
    ASSERT_NE(ret, 0);
}
/**********************************************************************************************************/

/**
 * @tc.name: UsbdSetInterface001
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetInterface001, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_0;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdSetInterface002
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetInterface002, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_0;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface003
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetInterface003, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_INVALID;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface004
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetInterface004, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_INVALID;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    interfaceId = INTERFACEID_INVALID;
    ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface005
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetInterface005, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_0;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface006
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetInterface006, TestSize.Level1)
{
    int32_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_1;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    interfaceId = INTERFACEID_INVALID;
    ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface007
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, devAddr && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetInterface007, TestSize.Level1)
{
    int32_t interfaceId = INTERFACEID_OK;
    uint8_t altIndex = INDEX_INVALID;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    interfaceId = INTERFACEID_INVALID;
    ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdSetInterface008
 * @tc.desc: Test functions to SetInterface
 * @tc.desc: int32_t SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdSetInterface008, TestSize.Level1)
{
    uint8_t altIndex = INDEX_INVALID;
    int32_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    interfaceId = INTERFACEID_INVALID;
    ret = g_usbInterface->SetInterface(dev, interfaceId, altIndex);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor001
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetDeviceDescriptor(dev, devData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor002
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetDeviceDescriptor(dev, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor003
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor003, TestSize.Level1)
{
    uint8_t devAddr = DEV_ADDR_INVALID;
    struct UsbDev dev = {dev_.busNum, devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetDeviceDescriptor(dev, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor004
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor004, TestSize.Level1)
{
    uint8_t busNum = BUS_NUM_INVALID;
    uint8_t devAddr = DEV_ADDR_INVALID;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetDeviceDescriptor(dev, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor005
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && length error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor005, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> devData(0);
    auto ret = g_usbInterface->GetDeviceDescriptor(dev, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor006
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr && length error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor006, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(0);
    auto ret = g_usbInterface->GetDeviceDescriptor(dev, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor007
 * @tc.desc: Test functions to GetDeviceDescriptor
 * @tc.desc: int32_t GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && length error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetDeviceDescriptor007, TestSize.Level1)
{
    uint8_t busNum = BUS_NUM_INVALID;
    uint8_t devAddr = DEV_ADDR_INVALID;
    struct UsbDev dev = {busNum, devAddr};
    std::vector<uint8_t> devData(0);
    auto ret = g_usbInterface->GetDeviceDescriptor(dev, devData);
    ASSERT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdDescriptor001
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor001, TestSize.Level1)
{
    uint8_t stringId = 0;
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetStringDescriptor(dev, stringId, devData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor002
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor002, TestSize.Level1)
{
    uint8_t stringId = 1;
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetStringDescriptor(dev, stringId, devData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor003
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, stringId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor003, TestSize.Level1)
{
    uint8_t stringId = INVALID_NUM;
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetStringDescriptor(dev, stringId, devData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor004
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor004, TestSize.Level1)
{
    uint8_t stringId = 0;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetStringDescriptor(dev, stringId, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor005
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor005, TestSize.Level1)
{
    uint8_t stringId = 0;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetStringDescriptor(dev, stringId, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor006
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor006, TestSize.Level1)
{
    uint8_t stringId = 0;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetStringDescriptor(dev, stringId, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor007
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr && stringID error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor007, TestSize.Level1)
{
    uint8_t stringId = STRING_ID_INVALID;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetStringDescriptor(dev, stringId, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor008
 * @tc.desc: Test functions to GetStringDescriptor
 * @tc.desc: int32_t GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && stringID error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetStringDescriptor008, TestSize.Level1)
{
    uint8_t stringId = STRING_ID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetStringDescriptor(dev, stringId, devData);
    ASSERT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdDescriptor001
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor001, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_0;
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetConfigDescriptor(dev, configId, devData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdDescriptor002
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor002, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_0;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetConfigDescriptor(dev, configId, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor003
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor003, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_0;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetConfigDescriptor(dev, configId, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor004
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor004, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_INVALID;
    struct UsbDev dev = dev_;
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    std::vector<uint8_t> tmpData(MAX_BUFFER_LENGTH, 1);
    auto ret = g_usbInterface->GetConfigDescriptor(dev, configId, devData);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(devData, tmpData);
}

/**
 * @tc.name: UsbdDescriptor005
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor005, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_0;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetConfigDescriptor(dev, configId, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor006
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor006, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetConfigDescriptor(dev, configId, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor007
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr && configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor007, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_INVALID;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetConfigDescriptor(dev, configId, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdDescriptor008
 * @tc.desc: Test functions to GetConfigDescriptor
 * @tc.desc: int32_t GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && configId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetConfigDescriptor008, TestSize.Level1)
{
    uint8_t configId = CONFIG_ID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    std::vector<uint8_t> devData(MAX_BUFFER_LENGTH);
    auto ret = g_usbInterface->GetConfigDescriptor(dev, configId, devData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetRawDescriptor001
 * @tc.desc: Test functions to GetRawDescriptor
 * @tc.desc: int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetRawDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    std::vector<uint8_t> rawData;
    auto ret = g_usbInterface->GetRawDescriptor(dev, rawData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdGetRawDescriptor002
 * @tc.desc: Test functions to GetRawDescriptor
 * @tc.desc: int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetRawDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    std::vector<uint8_t> rawData;
    auto ret = g_usbInterface->GetRawDescriptor(dev, rawData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdGetRawDescriptor003
 * @tc.desc: Test functions to GetRawDescriptor
 * @tc.desc: int32_t GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdGetRawDescriptor003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    std::vector<uint8_t> rawData;
    auto ret = g_usbInterface->GetRawDescriptor(dev, rawData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: GetFileDescriptor001
 * @tc.desc: Test functions to GetFileDescriptor
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetFileDescriptor001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t fd = 0;
    auto ret = g_usbInterface->GetFileDescriptor(dev, fd);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: GetFileDescriptor002
 * @tc.desc: Test functions to GetFileDescriptor
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetFileDescriptor002, TestSize.Level1)
{
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    int32_t fd = 0;
    auto ret = g_usbInterface->GetFileDescriptor(dev, fd);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: GetFileDescriptor003
 * @tc.desc: Test functions to GetFileDescriptor
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetFileDescriptor003, TestSize.Level1)
{
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    int32_t fd = 0;
    auto ret = g_usbInterface->GetFileDescriptor(dev, fd);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: GetFileDescriptor004
 * @tc.desc: Test functions to GetFileDescriptor
 * @tc.desc: int32_t GetFileDescriptor(const UsbDev &dev, int32_t &fd);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, GetFileDescriptor004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    int32_t fd = MAX_BUFFER_LENGTH;
    auto ret = g_usbInterface->GetFileDescriptor(dev, fd);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest001
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest002
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest003
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue003, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest004
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uin        t8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    interfaceId = INVALID_NUM;
    dev.busNum = BUS_NUM_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest005
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest006
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceId && pointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue006, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    interfaceId = INVALID_NUM;
    pointId = INVALID_NUM;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest007
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'w', 'r', 'i', 't', 'e'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '7'};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest008
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, interfaceId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue008, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    auto ret = g_usbInterface->ClaimInterface(dev, INTERFACEID_OK, 1);
    ASSERT_EQ(0, ret);
    uint8_t interfaceId = INVALID_NUM;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'w', 'r', 'i', 't', 'e'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '8'};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest009
 * @tc.desc: Test functions to RequestQueue
 * @tc.desc: int32_t RequestQueue(const UsbDev &dev, const UsbPipe &pipe, std::vector<uint8_t> &clientData,
        std::vector<uint8_t> &buffer);
 * @tc.desc: Negative test: parameters exception, interfaceId && pointId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestQueue009, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, INTERFACEID_OK, 1);
    ASSERT_EQ(0, ret);
    uint8_t interfaceId = INVALID_NUM;
    uint8_t pointId = INVALID_NUM;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'w', 'r', 'i', 't', 'e'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '9'};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdRequest001
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestWait001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> waitData(TAG_NUM_10);
    ret = g_usbInterface->RequestWait(dev, waitData, bufferData, TIME_WAIT);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest002
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestWait002, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    std::vector<uint8_t> waitData(TAG_NUM_10);
    ret = g_usbInterface->RequestWait(dev, waitData, bufferData, TIME_WAIT);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest003
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestWait003, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    std::vector<uint8_t> waitData(TAG_NUM_10);
    ret = g_usbInterface->RequestWait(dev, waitData, bufferData, TIME_WAIT);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdRequest004
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Negative test: parameters exception, devAddr && busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestWait004, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    std::vector<uint8_t> waitData(TAG_NUM_10);
    ret = g_usbInterface->RequestWait(dev, waitData, bufferData, TIME_WAIT);
    ASSERT_NE(0, ret);
}

/**
 * @tc.name: UsbdRequest005
 * @tc.desc: Test functions to RequestWait
 * @tc.desc: int32_t RequestWait(const UsbDev &dev, std::vector<uint8_t> &clientData, std::vector<uint8_t> &buffer,
 * int32_t timeout);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestWait005, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData(MAX_BUFFER_LENGTH);
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> waitData(TAG_NUM_10);
    dev.devAddr = DEV_ADDR_INVALID;
    dev.busNum = BUS_NUM_INVALID;
    ret = g_usbInterface->RequestWait(dev, waitData, bufferData, TIME_WAIT);
    ASSERT_NE(ret, 0);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdRequest001
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel001, TestSize.Level1)
{
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '1'};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest002
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '2'};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_NE(ret, 0);
    dev = dev_;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest003
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_IN;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '3'};
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_NE(ret, 0);
    dev = dev_;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest004
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: intfId && endpointId error in pipe but not used
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'r', 'e', 'a', 'd'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '4'};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    pipe.intfId = INTERFACEID_INVALID;
    pipe.endpointId = POINTID_INVALID;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_EQ(0, ret);
    pipe = {interfaceId, pointId};
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest005
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: call twice
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'w', 'r', 'i', 't', 'e'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '5'};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_EQ(0, ret);
    dev = dev_;
    pipe = {interfaceId, pointId};
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest006
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum error && interfaceid ignore
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel006, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'w', 'r', 'i', 't', 'e'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '6'};
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    pipe.intfId = INVALID_NUM;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_NE(ret, 0);
    dev.busNum = dev_.busNum;
    pipe.intfId = INTERFACEID_OK;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest007
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, devAddr error && interfaceid ignore
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel007, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'w', 'r', 'i', 't', 'e'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '7'};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    dev.devAddr = DEV_ADDR_INVALID;
    pipe.intfId = INTERFACEID_INVALID;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_NE(ret, 0);
    dev.devAddr = dev_.devAddr;
    pipe.intfId = INTERFACEID_OK;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdRequest008
 * @tc.desc: Test functions to RequestCancel
 * @tc.desc: int32_t RequestCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum error && devAddr error && interfaceid ignore
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdRequestCancel008, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t pointId = POINTID_DIR_OUT;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ClaimInterface(dev, interfaceId, 1);
    ASSERT_EQ(0, ret);
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    std::vector<uint8_t> clientData = {'q', 'u', 'e', 'u', 'e', 'w', 'r', 'i', 't', 'e'};
    std::vector<uint8_t> bufferData = {'r', 'e', 'q', 'u', 'e', 's', 't', '0', '0', '8'};
    ret = g_usbInterface->RequestQueue(dev, pipe, clientData, bufferData);
    ASSERT_EQ(0, ret);
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    pipe.intfId = INTERFACEID_INVALID;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_NE(ret, 0);
    dev = dev_;
    pipe.intfId = INTERFACEID_OK;
    ret = g_usbInterface->RequestCancel(dev, pipe);
    ASSERT_EQ(0, ret);
}

/**********************************************************************************************************/

/**
 * @tc.name: UsbdReleaseInterface001
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    auto ret = g_usbInterface->ReleaseInterface(dev, interfaceId);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: UsbdReleaseInterface002
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface002, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {BUS_NUM_INVALID, dev_.devAddr};
    auto ret = g_usbInterface->ReleaseInterface(dev, interfaceId);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface003
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface003, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->ReleaseInterface(dev, interfaceId);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface004
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface004, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = dev_;
    auto ret = g_usbInterface->ReleaseInterface(dev, interfaceId);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface005
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface005, TestSize.Level1)
{
    uint8_t interfaceId = INTERFACEID_OK;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->ReleaseInterface(dev, interfaceId);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface006
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface006, TestSize.Level1)
{
    int32_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {DEV_ADDR_INVALID, dev_.devAddr};
    auto ret = g_usbInterface->ReleaseInterface(dev, interfaceId);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface007
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface007, TestSize.Level1)
{
    int32_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {dev_.busNum, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->ReleaseInterface(dev, interfaceId);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: UsbdReleaseInterface008
 * @tc.desc: Test functions to ReleaseInterface
 * @tc.desc: int32_t ReleaseInterface(const UsbDev &dev, uint8_t interfaceId);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, UsbdReleaseInterface008, TestSize.Level1)
{
    int32_t interfaceId = INTERFACEID_INVALID;
    struct UsbDev dev = {BUS_NUM_INVALID, DEV_ADDR_INVALID};
    auto ret = g_usbInterface->ReleaseInterface(dev, interfaceId);
    ASSERT_NE(ret, 0);
}

/**
 * @tc.name: BulkCancel001
 * @tc.desc: Test functions to BulkCancel
 * @tc.desc: int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, BulkCancel001, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    ret = g_usbInterface->BulkCancel(dev, pipe);
    ASSERT_EQ(0, ret);
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: BulkCancel002
 * @tc.desc: Test functions to BulkCancel
 * @tc.desc: int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, BulkCancel002, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    dev.busNum = BUS_NUM_INVALID;
    ret = g_usbInterface->BulkCancel(dev, pipe);
    ASSERT_NE(0, ret);
    dev = dev_;
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: BulkCancel003
 * @tc.desc: Test functions to BulkCancel
 * @tc.desc: int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, devAddr error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, BulkCancel003, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    dev.devAddr = DEV_ADDR_INVALID;
    ret = g_usbInterface->BulkCancel(dev, pipe);
    ASSERT_NE(0, ret);
    dev = dev_;
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: BulkCancel004
 * @tc.desc: Test functions to BulkCancel
 * @tc.desc: int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, busNum && devAddr && interfaceid error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, BulkCancel004, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    dev.busNum = BUS_NUM_INVALID;
    dev.devAddr = DEV_ADDR_INVALID;
    pipe.intfId = POINTID_INVALID;
    ret = g_usbInterface->BulkCancel(dev, pipe);
    ASSERT_NE(0, ret);
    dev = dev_;
    pipe = {interfaceId, pointId};
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: BulkCancel005
 * @tc.desc: Test functions to BulkCancel
 * @tc.desc: int32_t BulkCancel(const UsbDev &dev, const UsbPipe &pipe);
 * @tc.desc: Negative test: parameters exception, intfId error
 * @tc.type: FUNC
 */
HWTEST_F(UsbdRequestTest, BulkCancel005, TestSize.Level1)
{
    struct UsbDev dev = dev_;
    uint8_t interfaceId = INTERFACEID_OK;
    uint8_t pointId = POINTID_DIR_IN;
    OHOS::HDI::Usb::V1_0::UsbPipe pipe = {interfaceId, pointId};
    sptr<UsbdBulkCallbackTest> usbdBulkCallback = new UsbdBulkCallbackTest();
    auto ret = g_usbInterface->RegBulkCallback(dev, pipe, usbdBulkCallback);
    ASSERT_EQ(ret, 0);
    pipe.intfId = POINTID_INVALID;
    ret = g_usbInterface->BulkCancel(dev, pipe);
    ASSERT_NE(0, ret);
    pipe = {interfaceId, pointId};
    ret = g_usbInterface->UnRegBulkCallback(dev, pipe);
    ASSERT_EQ(ret, 0);
}
} // namespace
