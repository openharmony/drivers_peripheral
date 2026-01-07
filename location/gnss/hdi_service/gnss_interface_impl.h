/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_LOCATION_LOCATION_GNSS_V2_0_GNSSINTERFACEIMPL_H
#define OHOS_HDI_LOCATION_LOCATION_GNSS_V2_0_GNSSINTERFACEIMPL_H

#include "v2_0/ignss_interface.h"

#include "iremote_object.h"
#include "location_vendor_interface.h"
#include "location_vendor_lib.h"
namespace OHOS {
namespace HDI {
namespace Location {
namespace Gnss {
namespace V2_0 {

void NmeaCallback(int64_t timestamp, const char* nmea, int length);
void GetGnssCallbackMethods(GnssCallbackStruct* device);
void GetGnssBasicCallbackMethods(GnssBasicCallbackIfaces* device);
void GetGnssCacheCallbackMethods(GnssCacheCallbackIfaces* device);
void SvStatusCallback(GnssSatelliteStatus* svInfo);
void GnssWorkingStatusUpdate(uint16_t* status);
void GnssMeasurementUpdate(OHOS::HDI::Location::GnssMeasurementInfo* gnssMeasurementInfo);
void LocationUpdate(GnssLocation* location);
void SetGnssClock(OHOS::HDI::Location::Gnss::V2_0::GnssMeasurementInfo* gnssMeasurementInfoNew,
    OHOS::HDI::Location::GnssMeasurementInfo* gnssMeasurementInfo);
void NiNotifyCallback(OHOS::HDI::Location::GnssNiNotificationRequest *notification);
void GetGnssMeasurementCallbackMethods(GnssMeasurementCallbackIfaces* device);

class GnssInterfaceImpl : public IGnssInterface {
public:
    GnssInterfaceImpl();
    ~GnssInterfaceImpl() override;

    int32_t SetGnssConfigPara(const GnssConfigPara& para) override;

    int32_t EnableGnss(const sptr<IGnssCallback>& callbackObj) override;

    int32_t DisableGnss() override;

    int32_t StartGnss(GnssStartType type) override;

    int32_t StopGnss(GnssStartType type) override;

    int32_t SetGnssReferenceInfo(const GnssRefInfo& refInfo) override;

    int32_t DeleteAuxiliaryData(unsigned short data) override;

    int32_t SetPredictGnssData(const std::string& data) override;

    int32_t GetCachedGnssLocationsSize(int32_t& size) override;

    int32_t GetCachedGnssLocations() override;

    int32_t SendNiUserResponse(int32_t gnssNiNotificationId, GnssNiResponseCmd userResponse) override;

    int32_t SendNetworkInitiatedMsg(const std::string& msg, int32_t length) override;

    int32_t EnableGnssMeasurement(const sptr<IGnssMeasurementCallback>& callbackObj) override;

    int32_t DisableGnssMeasurement() override;

    void ResetGnss();
private:
    int32_t AddGnssDeathRecipient(const sptr<IGnssCallback>& callbackObj);

    int32_t RemoveGnssDeathRecipient(const sptr<IGnssCallback>& callbackObj);

    void ResetGnssDeathRecipient();
};

class GnssCallBackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit GnssCallBackDeathRecipient(const wptr<GnssInterfaceImpl>& impl) : gnssInterfaceImpl_(impl) {};
    ~GnssCallBackDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject>& remote) override
    {
        (void)remote;
        sptr<GnssInterfaceImpl> impl = gnssInterfaceImpl_.promote();
        if (impl != nullptr) {
            impl->ResetGnss();
        }
    };
private:
    wptr<GnssInterfaceImpl> gnssInterfaceImpl_;
};
} // V2_0
} // Gnss
} // Location
} // HDI
} // OHOS

#endif // OHOS_HDI_LOCATION_LOCATION_GNSS_V2_0_GNSSINTERFACEIMPL_H
