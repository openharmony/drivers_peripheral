/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "hdi_gnss_event_callback_mock.h"

namespace OHOS {
namespace HDI {
namespace Location {
namespace Gnss {
namespace V2_0 {

int32_t GnssEventCallbackMock::ReportGnssWorkingStatus(GnssWorkingStatus status)
{
    return HDF_SUCCESS;
}

int32_t GnssEventCallbackMock::ReportLocation(const LocationInfo& location)
{
    return HDF_SUCCESS;
}

int32_t GnssEventCallbackMock::ReportNmea(int64_t timestamp, const std::string& nmea, int32_t length)
{
    return HDF_SUCCESS;
}

int32_t GnssEventCallbackMock::ReportGnssCapabilities(unsigned int capabilities)
{
    return HDF_SUCCESS;
}

int32_t GnssEventCallbackMock::ReportSatelliteStatusInfo(const SatelliteStatusInfo& info)
{
    return HDF_SUCCESS;
}

int32_t GnssEventCallbackMock::RequestGnssReferenceInfo(GnssRefInfoType type)
{
    return HDF_SUCCESS;
}

int32_t GnssEventCallbackMock::RequestPredictGnssData()
{
    return HDF_SUCCESS;
}

int32_t GnssEventCallbackMock::ReportCachedLocation(const std::vector<LocationInfo>& gnssLocations)
{
    return HDF_SUCCESS;
}

int32_t GnssEventCallbackMock::ReportGnssNiNotification(const GnssNiNotificationRequest& notification)
{
    return HDF_SUCCESS;
}
} // V2_0
} // Gnss
} // Location
} // HDI
} // OHOS