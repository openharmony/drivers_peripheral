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

#ifndef OHOS_HDI_LOCATION_LOCATION_GNSS_V1_0_GNSSINTERFACEIMPL_H
#define OHOS_HDI_LOCATION_LOCATION_GNSS_V1_0_GNSSINTERFACEIMPL_H

#include "v1_0/ignss_interface.h"

namespace OHOS {
namespace HDI {
namespace Location {
namespace Gnss {
namespace V1_0 {
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

    int32_t DeleteAuxiliaryData(GnssAuxiliaryData data) override;

    int32_t SetPredictGnssData(const std::string& data) override;

    int32_t GetCachedGnssLocationsSize(int32_t& size) override;

    int32_t GetCachedGnssLocations() override;
};
} // V1_0
} // Gnss
} // Location
} // HDI
} // OHOS

#endif // OHOS_HDI_LOCATION_LOCATION_GNSS_V1_0_GNSSINTERFACEIMPL_H