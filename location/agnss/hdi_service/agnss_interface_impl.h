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

#ifndef OHOS_HDI_LOCATION_LOCATION_AGNSS_V1_0_AGNSSINTERFACEIMPL_H
#define OHOS_HDI_LOCATION_LOCATION_AGNSS_V1_0_AGNSSINTERFACEIMPL_H

#include "v1_0/ia_gnss_interface.h"

namespace OHOS {
namespace HDI {
namespace Location {
namespace Agnss {
namespace V1_0 {
class AGnssInterfaceImpl : public IAGnssInterface {
public:
    AGnssInterfaceImpl();
    ~AGnssInterfaceImpl() override;

    int32_t SetAgnssCallback(const sptr<IAGnssCallback>& callbackObj) override;

    int32_t SetAgnssServer(const AGnssServerInfo& server) override;

    int32_t SetAgnssRefInfo(const AGnssRefInfo& refInfo) override;

    int32_t SetSubscriberSetId(const SubscriberSetId& id) override;
};
} // V1_0
} // Agnss
} // Location
} // HDI
} // OHOS

#endif // OHOS_HDI_LOCATION_LOCATION_AGNSS_V1_0_AGNSSINTERFACEIMPL_H
