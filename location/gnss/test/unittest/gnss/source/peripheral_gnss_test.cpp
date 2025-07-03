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

#include "string_ex.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include "gnss_interface_impl.h"
#include "peripheral_gnss_test.h"
#include "location_vendor_lib.h"
#include "gnss_measurement_callback_test.h"
#include "hdi_gnss_event_callback_mock.h"
#include "string_utils.h"
#include "v2_0/ignss_interface.h"

using namespace testing;
using namespace testing::ext;
using OHOS::HDI::Location::Gnss::V2_0::IGnssInterface;
using OHOS::HDI::Location::Gnss::V2_0::IGnssCallback;
using OHOS::HDI::Location::Gnss::V2_0::IGnssMeasurementCallback;
using OHOS::HDI::Location::Gnss::V2_0::GNSS_START_TYPE_NORMAL;
using OHOS::HDI::Location::Gnss::V2_0::GNSS_WORKING_STATUS_NONE;
using OHOS::HDI::Location::Gnss::V2_0::GNSS_WORKING_STATUS_SESSION_BEGIN;
using OHOS::HDI::Location::Gnss::V2_0::GNSS_WORKING_STATUS_SESSION_END;
using OHOS::HDI::Location::Gnss::V2_0::GNSS_WORKING_STATUS_ENGINE_ON;
using OHOS::HDI::Location::Gnss::V2_0::GNSS_WORKING_STATUS_ENGINE_OFF;
using OHOS::HDI::Location::Gnss::V2_0::GnssAuxiliaryDataType;
using OHOS::HDI::Location::Gnss::V2_0::GnssWorkingMode;
using OHOS::HDI::Location::Gnss::V2_0::GnssConfigPara;
using OHOS::HDI::Location::Gnss::V2_0::GnssRefInfoType;
using OHOS::HDI::Location::Gnss::V2_0::GnssRefInfo;
using OHOS::HDI::Location::Gnss::V2_0::GnssLocationValidity;

namespace OHOS {
namespace HDI {
namespace Location {
namespace Gnss {
namespace V2_0 {

void PeripheralGnssTest::SetUp()
{
    gnssInstance_ = new (std::nothrow) GnssInterfaceImpl();
}

void PeripheralGnssTest::TearDown()
{
    gnssInstance_ = nullptr;
    LocationVendorInterface::DestroyInstance();
}

HWTEST_F(PeripheralGnssTest, SetGnssConfigParaTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, SetGnssConfigParaTest001, TestSize.Level1";

    GnssConfigPara para;
    para.gnssBasic.gnssMode = GNSS_WORKING_MODE_MS_ASSISTED;
    gnssInstance_->SetGnssConfigPara(para);
    EXPECT_NE(gnssInstance_, nullptr);
}

HWTEST_F(PeripheralGnssTest, NmeaCallbackTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, NmeaCallbackTest001, TestSize.Level1";

    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    auto gnssCallback_ = new (std::nothrow) GnssEventCallbackMock(saObject);
 
    gnssInstance_->EnableGnss(gnssCallback_);
    EXPECT_NE(gnssInstance_, nullptr);

    NmeaCallback(0, nullptr, 0);
    NmeaCallback(0, "nmea_str.", 0);
    gnssInstance_->DisableGnss();
    sleep(1);
}

HWTEST_F(PeripheralGnssTest, GetGnssCallbackMethodsTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
       << "PeripheralGnssTest, GetGnssCallbackMethodsTest001, TestSize.Level1";

    // sub reg null brach test
    GetGnssBasicCallbackMethods(nullptr);
    GetGnssCacheCallbackMethods(nullptr);
    
    GetGnssCallbackMethods(nullptr);
    GnssCallbackStruct device;
    GetGnssCallbackMethods(&device);
    EXPECT_NE(gnssInstance_, nullptr);
}

HWTEST_F(PeripheralGnssTest, SvStatusCallbackTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, SvStatusCallbackTest001, TestSize.Level1";

    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    auto gnssCallback_ = new (std::nothrow) GnssEventCallbackMock(saObject);
    gnssInstance_->EnableGnss(gnssCallback_);
    EXPECT_NE(gnssInstance_, nullptr);
    SvStatusCallback(nullptr);
    GnssSatelliteStatus gnssSatelliteStatus;
    gnssSatelliteStatus.satellitesNum = 1;
    SvStatusCallback(&gnssSatelliteStatus);
    
    gnssInstance_->DisableGnss();
    sleep(1);
}

HWTEST_F(PeripheralGnssTest, GnssWorkingStatusUpdateTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, GnssWorkingStatusUpdateTest001, TestSize.Level1";

    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    auto gnssCallback_ = new (std::nothrow) GnssEventCallbackMock(saObject);

    gnssInstance_->EnableGnss(gnssCallback_);
    EXPECT_NE(gnssInstance_, nullptr);
    GnssWorkingStatusUpdate(nullptr);
    uint16_t statusPtr = 1;
    GnssWorkingStatusUpdate(&statusPtr);
    gnssInstance_->DisableGnss();
    sleep(1);
}

HWTEST_F(PeripheralGnssTest, LocationUpdateTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, LocationUpdateTest001, TestSize.Level1";

    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    auto gnssCallback_ = new (std::nothrow) GnssEventCallbackMock(saObject);

    gnssInstance_->EnableGnss(gnssCallback_);
    EXPECT_NE(gnssInstance_, nullptr);
    
    LocationUpdate(nullptr);
    GnssLocation location;
    location.latitude = 31.0;
    LocationUpdate(&location);
    gnssInstance_->DisableGnss();
    sleep(1);
}

HWTEST_F(PeripheralGnssTest, NiNotifyCallbackTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, NiNotifyCallbackTest001, TestSize.Level1";

    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    auto gnssCallback_ = new (std::nothrow) GnssEventCallbackMock(saObject);

    gnssInstance_->EnableGnss(gnssCallback_);
    EXPECT_NE(gnssInstance_, nullptr);
    
    NiNotifyCallback(nullptr);
    OHOS::HDI::Location::GnssNiNotificationRequest notification;
    NiNotifyCallback(&notification);
    gnssInstance_->DisableGnss();
    sleep(1);
}

HWTEST_F(PeripheralGnssTest, SendNiUserResponseTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, SendNiUserResponseTest001, TestSize.Level1";

    HDF_LOGI("PeripheralGnssTest, SendNiUserResponseTest001, TestSize.Level1");
    GnssNiResponseCmd userResponse = GnssNiResponseCmd::GNSS_NI_RESPONSE_CMD_ACCEPT;
    gnssInstance_->SendNiUserResponse(200, userResponse);
    EXPECT_NE(gnssInstance_, nullptr);
    gnssInstance_->SendNetworkInitiatedMsg("0", 0);
    gnssInstance_->SendNetworkInitiatedMsg("0x20", 4);
}

HWTEST_F(PeripheralGnssTest, EnableGnssTest001, TestSize.Level1)
{
    HDF_LOGI("PeripheralGnssTest, EnableGnssTest001, TestSize.Level1");

    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    auto gnssCallback_ = new (std::nothrow) GnssEventCallbackMock(saObject);

    gnssInstance_->EnableGnss(gnssCallback_);
    EXPECT_NE(gnssInstance_, nullptr);
    HDF_LOGI("PeripheralGnssTest, EnableGnssTest001, TestSize.Level1");
    gnssInstance_->DisableGnss();
    sleep(1);
}

HWTEST_F(PeripheralGnssTest, EnableGnssMeasurementTest001, TestSize.Level1)
{
    HDF_LOGI("PeripheralGnssTest, EnableGnssMeasurementTest001, TestSize.Level1");

    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    auto gnssCallback_ = new (std::nothrow) GnssEventCallbackMock(saObject);

    gnssInstance_->EnableGnss(gnssCallback_);
    
    gnssInstance_->EnableGnssMeasurement(nullptr);
    gnssMeasurementCallback_ = new (std::nothrow) GnssMeasurementCallbackTest(saObject);
    gnssInstance_->EnableGnssMeasurement(gnssMeasurementCallback_);
    
    OHOS::HDI::Location::GnssMeasurementInfo gnssMeasurementInfo;
    gnssMeasurementInfo.size = 2;
    GnssMeasurementUpdate(&gnssMeasurementInfo);
    GnssMeasurementUpdate(nullptr);

    HDF_LOGI("PeripheralGnssTest, EnableGnssMeasurementTest001, TestSize.Level1");
    EXPECT_NE(gnssInstance_, nullptr);
    gnssInstance_->DisableGnss();
    sleep(1);
}

HWTEST_F(PeripheralGnssTest, DisableGnssMeasurementTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, DisableGnssMeasurementTest001, TestSize.Level1";

    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    auto gnssCallback_ = new (std::nothrow) GnssEventCallbackMock(saObject);

    gnssInstance_->EnableGnss(gnssCallback_);

    EXPECT_NE(nullptr, gnssInstance_);
    if (gnssInstance_ != nullptr) {
        gnssInstance_->DisableGnssMeasurement();
    }
    gnssInstance_->DisableGnss();
    sleep(1);
}

HWTEST_F(PeripheralGnssTest, SetGnssReferenceInfoTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, SetGnssReferenceInfoTest001, TestSize.Level1";

    EXPECT_NE(nullptr, gnssInstance_);
    int32_t ret = 0;

    if (gnssInstance_ != nullptr) {
        GnssRefInfo refInfo;
        refInfo.type = GnssRefInfoType::GNSS_REF_INFO_TIME;
        ret = gnssInstance_->SetGnssReferenceInfo(refInfo);
        refInfo.type = GnssRefInfoType::GNSS_REF_INFO_LOCATION;
        ret = gnssInstance_->SetGnssReferenceInfo(refInfo);
        refInfo.type = GnssRefInfoType::GNSS_REF_INFO_BEST_LOCATION;
        ret = gnssInstance_->SetGnssReferenceInfo(refInfo);
    }
    HDF_LOGI("test ret:%{public}d", ret);
}

HWTEST_F(PeripheralGnssTest, DeleteAuxiliaryData001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, DeleteAuxiliaryData001, TestSize.Level1";

    EXPECT_NE(nullptr, gnssInstance_);

    if (gnssInstance_ != nullptr) {
        unsigned short data = 0;
        gnssInstance_->DeleteAuxiliaryData(data);
    }
}

HWTEST_F(PeripheralGnssTest, SetPredictGnssDataTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, SetPredictGnssDataTest001, TestSize.Level1";
    EXPECT_NE(nullptr, gnssInstance_);
    if (gnssInstance_ != nullptr) {
        std::string data = "test";
        int32_t ret = gnssInstance_->SetPredictGnssData(data);
        HDF_LOGI("test ret:%{public}d", ret);
    }
}

HWTEST_F(PeripheralGnssTest, GetCachedGnssLocationsSizeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, GetCachedGnssLocationsSizeTest001, TestSize.Level1";
    EXPECT_NE(nullptr, gnssInstance_);
    if (gnssInstance_ != nullptr) {
        int32_t size = 0;
        int32_t ret = gnssInstance_->GetCachedGnssLocationsSize(size);
        HDF_LOGI("test ret:%{public}d", ret);
    }
}

HWTEST_F(PeripheralGnssTest, GetCachedGnssLocationsTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, GetCachedGnssLocationsTest001, TestSize.Level1";
    EXPECT_NE(nullptr, gnssInstance_);
    if (gnssInstance_ != nullptr) {
        int32_t ret = gnssInstance_->GetCachedGnssLocations();
        HDF_LOGI("test ret:%{public}d", ret);
    }
}

HWTEST_F(PeripheralGnssTest, SendNiUserResponseTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, SendNiUserResponseTest002, TestSize.Level1";
    EXPECT_NE(nullptr, gnssInstance_);
    int32_t gnssNiNotificationId = 0;
    GnssNiResponseCmd userResponse = GnssNiResponseCmd::GNSS_NI_RESPONSE_CMD_ACCEPT;
    if (gnssInstance_ != nullptr) {
        int32_t ret = gnssInstance_->SendNiUserResponse(gnssNiNotificationId, userResponse);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

HWTEST_F(PeripheralGnssTest, SendNetworkInitiatedMsg001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, SendNetworkInitiatedMsg001, TestSize.Level1";
    EXPECT_NE(nullptr, gnssInstance_);
    if (gnssInstance_ != nullptr) {
        std::string msg = "test";
        int length = msg.length();
        int32_t ret = gnssInstance_->SendNetworkInitiatedMsg(msg, length);
        HDF_LOGI("test ret:%{public}d", ret);
    }
}

HWTEST_F(PeripheralGnssTest, StartGnssTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, StartGnssTest001, TestSize.Level1";
    int32_t ret = 0;
    
    ret = gnssInstance_->StartGnss(GNSS_START_TYPE_NORMAL);
    ret = gnssInstance_->StopGnss(GNSS_START_TYPE_NORMAL);
    HDF_LOGI("test ret:%{public}d", ret);
}

HWTEST_F(PeripheralGnssTest, DoubleEnableGnssTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, DoubleEnableGnssTest001, TestSize.Level1";

    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    auto gnssCallback_ = new (std::nothrow) GnssEventCallbackMock(saObject);

    auto ret = gnssInstance_->EnableGnss(gnssCallback_);
    sleep(1);
    auto gnssCallback_2 = new (std::nothrow) GnssEventCallbackMock(saObject);
    gnssInstance_->EnableGnss(gnssCallback_2);
    gnssInstance_->DisableGnss();
    HDF_LOGI("test ret:%{public}d", ret);
}

HWTEST_F(PeripheralGnssTest, GetGnssMeasurementCallbackMethodsTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, GetGnssMeasurementCallbackMethodsTest001, TestSize.Level1";
    GnssMeasurementCallbackIfaces device;
    GetGnssMeasurementCallbackMethods(nullptr);
    GetGnssMeasurementCallbackMethods(&device);
}

HWTEST_F(PeripheralGnssTest, GetModuleInterfaceTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, GetModuleInterfaceTest001, TestSize.Level1";

    auto locationVendorInterface = LocationVendorInterface::GetInstance();
    locationVendorInterface->GetModuleInterface(0);
    EXPECT_NE(gnssInstance_, nullptr);
}

HWTEST_F(PeripheralGnssTest, RestGnssTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, RestGnssTest001, TestSize.Level1";

    auto gnssImpl = new (std::nothrow) GnssInterfaceImpl();
    auto ret = gnssImpl->StartGnss(GNSS_START_TYPE_NORMAL);
    EXPECT_NE(gnssInstance_, nullptr);
    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    gnssMeasurementCallback_ = new (std::nothrow) GnssMeasurementCallbackTest(saObject);
    gnssImpl->EnableGnssMeasurement(gnssMeasurementCallback_);
    gnssImpl->ResetGnss();
    HDF_LOGI("test ret:%{public}d", ret);
}

HWTEST_F(PeripheralGnssTest, HexCharToIntTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralGnssTest, HexCharToIntTest001, TestSize.Level1";

    std::string str = "1234";
    std::vector<uint8_t> ret = StringUtils::HexToByteVector(str);
    EXPECT_NE(ret.size(), 10);
}

} // V2_0
} // Gnss
} // Location
} // HDI
} // OHOS
 