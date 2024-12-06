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

#ifndef HDI_GNSS_EVENT_CALLBACK_MOCK_H
#define HDI_GNSS_EVENT_CALLBACK_MOCK_H

#include <iproxy_broker.h>
#include "iremote_stub.h"
#include "iremote_object.h"
#include "iremote_broker.h"
#include <v2_0/ignss_callback.h>
#include <hdf_base.h>

namespace OHOS {
namespace HDI {
namespace Location {
namespace Gnss {
namespace V2_0 {
using HDI::Location::Gnss::V2_0::IGnssCallback;
using HDI::Location::Gnss::V2_0::LocationInfo;
using HDI::Location::Gnss::V2_0::GnssWorkingStatus;
using HDI::Location::Gnss::V2_0::GnssCapabilities;
using HDI::Location::Gnss::V2_0::SatelliteStatusInfo;
using HDI::Location::Gnss::V2_0::GnssRefInfoType;
using HDI::Location::Gnss::V2_0::GnssNiNotificationRequest;


class GnssEventCallbackMock : public IProxyBroker<IGnssCallback> {
public:
    explicit GnssEventCallbackMock(const sptr<IRemoteObject>& remote)
        : IProxyBroker<IGnssCallback>(remote) {
    }

    int32_t ReportLocation(const LocationInfo& location) override;
    int32_t ReportGnssWorkingStatus(GnssWorkingStatus status) override;
    int32_t ReportNmea(int64_t timestamp, const std::string& nmea, int32_t length) override;
    int32_t ReportGnssCapabilities(unsigned int capabilities) override;
    int32_t ReportSatelliteStatusInfo(const SatelliteStatusInfo& info) override;
    int32_t RequestGnssReferenceInfo(GnssRefInfoType type) override;
    int32_t RequestPredictGnssData() override;
    int32_t ReportCachedLocation(const std::vector<LocationInfo>& gnssLocations) override;
    int32_t ReportGnssNiNotification(const GnssNiNotificationRequest& notification) override;
};
} // V2_0
} // Gnss
} // Location
} // HDI
} // OHOS
#endif // GNSS_EVENT_CALLBACK_TEST_H
