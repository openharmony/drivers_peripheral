/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <hdf_log.h>
#include "../../../chip/hdi_service/wifi_sta_iface.h"
#include "wifi_hal_fn.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V2_0;

namespace WifiStaIfaceTest {
const std::string WLAN_IFNAME = "wlan0";
const std::string AP_IFNAME = "wlan1";
const std::string TEST_MAC = "000000";

class WifiStaIfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        std::vector<std::string> instances = {WLAN_IFNAME};
        ifaceTool = std::make_shared<IfaceTool>();
        ifaceUtil = std::make_shared<IfaceUtil>(ifaceTool);
        WifiHalFn fn;
        InitWifiHalFuncTable(&fn);
        wifiVendorHalTest = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
        staIface = new (std::nothrow) WifiStaIface(WLAN_IFNAME, wifiVendorHalTest, ifaceUtil);
        testIface = new (std::nothrow) WifiStaIface(AP_IFNAME, wifiVendorHalTest, ifaceUtil);
    }
    void TearDown()
    {
        wifiVendorHalTest.reset();
        ifaceTool.reset();
        ifaceUtil.reset();
    }

public:
    std::shared_ptr<WifiVendorHal> wifiVendorHalTest;
    std::shared_ptr<IfaceTool> ifaceTool;
    std::shared_ptr<IfaceUtil> ifaceUtil;
    sptr<WifiStaIface> staIface;
    sptr<WifiStaIface> testIface;
};

/**
 * @tc.name: WifiStaIfaceTest001
 * @tc.desc: wifiStaIface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiStaIfaceTest, WifiStaIfaceTest001, TestSize.Level1)
{
    HDF_LOGI("WifiStaIfaceTest001 started");
    staIface->Invalidate();
    EXPECT_FALSE(staIface->IsValid());
    staIface->IsValid();
    EXPECT_TRUE(staIface->GetName() == WLAN_IFNAME);
    IfaceType type = IfaceType::AP;
    EXPECT_TRUE(staIface->GetIfaceType(type) == HDF_SUCCESS);
    EXPECT_TRUE(type == IfaceType::STA);
    std::string name;
    EXPECT_TRUE(staIface->GetIfaceName(name) == HDF_SUCCESS);
    EXPECT_TRUE(name == WLAN_IFNAME);
}

HWTEST_F(WifiStaIfaceTest, SetDpiMarkRuleTest, TestSize.Level1)
{
    HDF_LOGI("SetDpiMarkRuleTest started");
    EXPECT_TRUE(staIface->SetDpiMarkRule(0, 0, 0) == HDF_SUCCESS);
    EXPECT_TRUE(staIface->SetDpiMarkRule(1, 1, 1) == HDF_FAILURE);
    EXPECT_TRUE(staIface->SetTxPower(0) == HDF_SUCCESS);
    EXPECT_TRUE(staIface->SetTxPower(1) == HDF_FAILURE);
}

HWTEST_F(WifiStaIfaceTest, EnablePowerModeTest, TestSize.Level1)
{
    HDF_LOGI("EnablePowerModeTest started");
    EXPECT_TRUE(staIface->EnablePowerMode(0) == HDF_SUCCESS);
    uint32_t cap;
    EXPECT_TRUE(staIface->GetIfaceCap(cap) == HDF_SUCCESS);
    EXPECT_TRUE(testIface->GetIfaceCap(cap) == HDF_FAILURE);
}

HWTEST_F(WifiStaIfaceTest, GetSupportFreqsTest, TestSize.Level1)
{
    HDF_LOGI("GetSupportFreqsTest started");
    std::vector<uint32_t> freqs;
    EXPECT_TRUE(staIface->GetSupportFreqs(0, freqs) == HDF_SUCCESS);
    EXPECT_TRUE(staIface->SetMacAddress(TEST_MAC) == HDF_SUCCESS);
    EXPECT_TRUE(staIface->SetCountryCode("cn") == HDF_SUCCESS);
    EXPECT_TRUE(staIface->SetPowerMode(0) == HDF_ERR_NOT_SUPPORT);
    int32_t mode;
    EXPECT_TRUE(staIface->GetPowerMode(mode) == HDF_ERR_NOT_SUPPORT);
}

HWTEST_F(WifiStaIfaceTest, RegisterChipIfaceCallBackTest, TestSize.Level1)
{
    HDF_LOGI("RegisterChipIfaceCallBackTest started");
    sptr<IChipIfaceCallback> ifaceCallback;
    EXPECT_TRUE(staIface->RegisterChipIfaceCallBack(ifaceCallback) == HDF_FAILURE);
    EXPECT_TRUE(staIface->UnRegisterChipIfaceCallBack(ifaceCallback) == HDF_FAILURE);
}

HWTEST_F(WifiStaIfaceTest, ScanTest, TestSize.Level1)
{
    HDF_LOGI("ScanTest started");
    ScanParams scanParam;
    scanParam.fastConnectFlag = 0;
    EXPECT_TRUE(staIface->StartScan(scanParam) == HDF_SUCCESS);
    scanParam.fastConnectFlag = 1;
    EXPECT_TRUE(staIface->StartScan(scanParam) == HDF_FAILURE);
    std::vector<ScanResultsInfo> scanInfo;
    staIface->GetScanInfos(scanInfo);
    SignalPollResult signalPollResult;
    staIface->GetSignalPollInfo(signalPollResult);
    PnoScanParams pnoParam;
    pnoParam.min2gRssi = 0;
    EXPECT_TRUE(staIface->StartPnoScan(pnoParam) == HDF_SUCCESS);
    pnoParam.min2gRssi = 1;
    EXPECT_TRUE(staIface->StartPnoScan(pnoParam) == HDF_FAILURE);
    EXPECT_TRUE(staIface->StopPnoScan() == HDF_SUCCESS);
}
}