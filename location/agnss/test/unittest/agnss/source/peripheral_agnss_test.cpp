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
#include "iremote_object.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "peripheral_agnss_test.h"
#include "agnss_interface_impl.h"
#include <iproxy_broker.h>
#include <v2_0/ia_gnss_callback.h>

using namespace testing;
using namespace testing::ext;
using OHOS::HDI::Location::Agnss::V2_0::IAGnssCallback;
using OHOS::HDI::Location::Agnss::V2_0::AGNSS_TYPE_SUPL;
using OHOS::HDI::Location::Agnss::V2_0::AGnssServerInfo;
using OHOS::HDI::Location::Agnss::V2_0::AGnssRefInfo;
namespace OHOS {
namespace HDI {
namespace Location {
namespace Agnss {
namespace V2_0 {

void PeripheralAGnssTest::SetUp()
{
    agnssInstance_ = new (std::nothrow) AGnssInterfaceImpl();
    isSupportGnss = OHOS::system::GetBoolParameter(SYSPARAM_GPS_SUPPORT, false);
}

void PeripheralAGnssTest::TearDown()
{
    agnssInstance_ = nullptr;
}

HWTEST_F(PeripheralAGnssTest, SetAgnssCallbackTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralAGnssTest, SetAgnssCallbackTest001, TestSize.Level1";
    if (!isSupportGnss) {
        GTEST_LOG_(INFO)
            << "PeripheralGnssTest, not support gnss, skip tdd.";
        return;
    }
    EXPECT_NE(nullptr, agnssInstance_);
    int32_t ret = 0;
    if (agnssInstance_ != nullptr) {
        sptr<ISystemAbilityManager> samgr =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);
    
        auto callbackObj2 = new (std::nothrow) AgnssEventCallbackMock(saObject);
        ret = agnssInstance_->SetAgnssCallback(callbackObj2);
    }
}

HWTEST_F(PeripheralAGnssTest, RequestSetupAgnssDataConnectionTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralAGnssTest, RequestSetupAgnssDataConnectionTest001, TestSize.Level1";
    if (!isSupportGnss) {
        GTEST_LOG_(INFO)
            << "PeripheralGnssTest, not support gnss, skip tdd.";
        return;
    }
    EXPECT_NE(nullptr, agnssInstance_);
    GetSetidCb(0);
    RequestSetupAgnssDataConnection(nullptr);
    AgnssDataConnectionRequest status;
    status.agnssCategory = 1;
    status.requestCategory = 2;
    RequestSetupAgnssDataConnection(&status);

    int32_t ret = 0;
    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> saObject = samgr->CheckSystemAbility(LOCATION_LOCATOR_SA_ID);

    auto callbackObj2 = new (std::nothrow) AgnssEventCallbackMock(saObject);
    ret = agnssInstance_->SetAgnssCallback(callbackObj2);
    
    GetSetidCb(0);
    RequestSetupAgnssDataConnection(&status);
}

HWTEST_F(PeripheralAGnssTest, SetAgnssServerTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralAGnssTest, SetAgnssServerTest001, TestSize.Level1";
    if (!isSupportGnss) {
        GTEST_LOG_(INFO)
            << "PeripheralGnssTest, not support gnss, skip tdd.";
        return;
    }
    EXPECT_NE(nullptr, agnssInstance_);
    if (agnssInstance_ != nullptr) {
        AGnssServerInfo server;
        server.type = AGNSS_TYPE_SUPL;
        server.port = 8700;
        int32_t ret = agnssInstance_->SetAgnssServer(server);
    }
}

HWTEST_F(PeripheralAGnssTest, SetAgnssRefInfoTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralAGnssTest, SetAgnssRefInfoTest001, TestSize.Level1";
    if (!isSupportGnss) {
        GTEST_LOG_(INFO)
            << "PeripheralGnssTest, not support gnss, skip tdd.";
        return;
    }
    EXPECT_NE(nullptr, agnssInstance_);
    AGnssRefInfo refInfo;
    refInfo.type = HDI::Location::Agnss::V2_0::ANSS_REF_INFO_TYPE_CELLID;
    refInfo.mac.mac = {2, 2, 2, 2, 21, 1};
    if (agnssInstance_ != nullptr) {
        GetRefLocationidCb(2);
        agnssInstance_->SetAgnssRefInfo(refInfo);
        GetRefLocationidCb(1);
        refInfo.cellId.type = HDI::Location::Agnss::V2_0::CELLID_TYPE_GSM;
        agnssInstance_->SetAgnssRefInfo(refInfo);
        refInfo.cellId.type = HDI::Location::Agnss::V2_0::CELLID_TYPE_UMTS;
        agnssInstance_->SetAgnssRefInfo(refInfo);
        refInfo.cellId.type = HDI::Location::Agnss::V2_0::CELLID_TYPE_NR;
        agnssInstance_->SetAgnssRefInfo(refInfo);
        refInfo.cellId.type = HDI::Location::Agnss::V2_0::CELLID_TYPE_LTE;
        agnssInstance_->SetAgnssRefInfo(refInfo);
    }
}

HWTEST_F(PeripheralAGnssTest, SetSubscriberSetIdTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralAGnssTest, SetSubscriberSetIdTest001, TestSize.Level1";
    if (!isSupportGnss) {
        GTEST_LOG_(INFO)
            << "PeripheralGnssTest, not support gnss, skip tdd.";
        return;
    }
    EXPECT_NE(nullptr, agnssInstance_);
    SubscriberSetId setId;
    setId.type = HDI::Location::Agnss::V2_0::AGNSS_SETID_TYPE_IMSI;
    if (agnssInstance_ != nullptr) {
        agnssInstance_->SetSubscriberSetId(setId);
    }
}

HWTEST_F(PeripheralAGnssTest, ResetAgnssTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO)
        << "PeripheralAGnssTest, ResetAgnssTest001, TestSize.Level1";
    if (!isSupportGnss) {
        GTEST_LOG_(INFO)
            << "PeripheralGnssTest, not support gnss, skip tdd.";
        return;
    }
    EXPECT_NE(nullptr, agnssInstance_);
    agnssInstance_->ResetAgnss();
}

} // V2_0
} // Gnss
} // Location
} // HDI
} // OHOS
