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
#include "../../../chip/hdi_service/wifi_vendor_hal.h"
#include "../../../chip/hdi_service/hdi_sync_util.h"
#include "v1_0/ichip_iface_callback.h"
#include "wifi_hal_fn.h"

using namespace testing::ext;
using namespace OHOS::HDI::Wlan::Chip::V1_0;

namespace WifiVendorHalTest {
const std::string VAILD_IFNAME = "wlan0";
const std::string INVAILD_IFNAME = "wlan2";

class WifiVendorHalTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        ifaceTool = std::make_shared<IfaceTool>();
        WifiHalFn fn = {};
        InitWifiHalFuncTable(&fn);
        wifiVendorHalTest = std::make_shared<WifiVendorHal>(ifaceTool, fn, true);
    }
    void TearDown()
    {
        wifiVendorHalTest.reset();
        ifaceTool.reset();
    }

    static void OnSubsystemRestartCallbackMock(const std::string& test)
    {
        HDF_LOGI("OnSubsystemRestartCallbackMock enter");
    }

    static void OnStopCompleteCallbackMock(const std::string& test)
    {
        HDF_LOGI("OnStopCompleteCallbackMock enter");
    }

    std::shared_ptr<WifiVendorHal> wifiVendorHalTest;
    std::shared_ptr<IfaceTool> ifaceTool;
    sptr<IChipIfaceCallback> ifaceCallback;

    void StartTest()
    {
        HDF_LOGI("StartTest started");
        EXPECT_TRUE(wifiVendorHalTest->Start() == HAL_SUCCESS);
        EXPECT_TRUE(wifiVendorHalTest->Initialize() == HAL_SUCCESS);
        wifiVendorHalTest->RegisterRestartCallback(OnSubsystemRestartCallbackMock);
        wifiVendorHalTest->SetCountryCode(VAILD_IFNAME, "cn");
        SignalPollResult res;
        wifiVendorHalTest->GetSignalPollInfo(VAILD_IFNAME, res);
        wifiVendorHalTest->GetPowerMode(VAILD_IFNAME);
        wifiVendorHalTest->SetPowerMode(VAILD_IFNAME, 0);
        wifiVendorHalTest->EnablePowerMode(VAILD_IFNAME, 0);
        wifiVendorHalTest->SetDpiMarkRule(0, 0, 0);
        wifiVendorHalTest->SetTxPower(VAILD_IFNAME, 0);
    }

    void ScanResultEventTest()
    {
        ScanParams scanParam;
        wifiVendorHalTest->StartScan(VAILD_IFNAME, scanParam);
        wifiVendorHalTest->OnAsyncGscanFullResult(0);
        wifiVendorHalTest->OnAsyncRssiReport(0, 0, 0);
        PnoScanParams pnoParam;
        wifiVendorHalTest->StartPnoScan(VAILD_IFNAME, pnoParam);
        wifiVendorHalTest->RegisterIfaceCallBack(VAILD_IFNAME, ifaceCallback);
        wifiVendorHalTest->UnRegisterIfaceCallBack(VAILD_IFNAME, ifaceCallback);
        wifiVendorHalTest->StopPnoScan(VAILD_IFNAME);
        std::vector<ScanResultsInfo> scanInfo;
        wifiVendorHalTest->GetScanInfos(VAILD_IFNAME, scanInfo);
    }

    void StopTest()
    {
        auto lock = AcquireGlobalLock();
        wifiVendorHalTest->Stop(&lock, [&]() {});
        wifiVendorHalTest->Start();
        wifiVendorHalTest->Stop(&lock, [&]() {});
    }

    void GetChipCapsTest()
    {
        uint32_t cap;
        EXPECT_TRUE(wifiVendorHalTest->GetChipCaps(VAILD_IFNAME, cap) == HAL_SUCCESS);
        EXPECT_TRUE(wifiVendorHalTest->GetChipCaps(INVAILD_IFNAME, cap) == HAL_UNKNOWN);
        EXPECT_TRUE(wifiVendorHalTest->GetSupportedFeatureSet(VAILD_IFNAME, cap) == HAL_SUCCESS);
        EXPECT_TRUE(wifiVendorHalTest->GetSupportedFeatureSet(INVAILD_IFNAME, cap) == HAL_UNKNOWN);
    }

    void GetValidFrequenciesForBandTest()
    {
        wifiVendorHalTest->GetValidFrequenciesForBand(VAILD_IFNAME, 0);
        wifiVendorHalTest->CreateVirtualInterface(VAILD_IFNAME, HalIfaceType::HAL_TYPE_STA);
        EXPECT_TRUE(wifiVendorHalTest->DeleteVirtualInterface(VAILD_IFNAME) == HAL_SUCCESS);
        EXPECT_TRUE(wifiVendorHalTest->DeleteVirtualInterface(INVAILD_IFNAME) == HAL_NOT_SUPPORTED);
    }
};

HWTEST_F(WifiVendorHalTest, StartTest, TestSize.Level1)
{
    StartTest();
}

HWTEST_F(WifiVendorHalTest, ScanResultEventTest, TestSize.Level1)
{
    ScanResultEventTest();
}

HWTEST_F(WifiVendorHalTest, StopTest, TestSize.Level1)
{
    StopTest();
}

HWTEST_F(WifiVendorHalTest, GetChipCapsTest, TestSize.Level1)
{
    GetChipCapsTest();
}

HWTEST_F(WifiVendorHalTest, GetValidFrequenciesForBandTest, TestSize.Level1)
{
    GetValidFrequenciesForBandTest();
}
}