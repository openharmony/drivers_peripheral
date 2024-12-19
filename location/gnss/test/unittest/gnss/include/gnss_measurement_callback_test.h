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

#ifndef GNSS_MEASUREMENT_CALLBACK_TEST_H
#define GNSS_MEASUREMENT_CALLBACK_TEST_H

#include <iproxy_broker.h>
#include "iremote_object.h"
#include <v2_0/ignss_interface.h>

 using OHOS::HDI::Location::Gnss::V2_0::IGnssInterface;
 using OHOS::HDI::Location::Gnss::V2_0::IGnssMeasurementCallback;
 using OHOS::HDI::Location::Gnss::V2_0::GnssMeasurementInfo;

namespace OHOS {
namespace HDI {
namespace Location {
namespace Gnss {
namespace V2_0 {
class GnssMeasurementCallbackTest : public IProxyBroker<IGnssMeasurementCallback> {
public:
    explicit GnssMeasurementCallbackTest(const sptr<IRemoteObject>& remote)
        : IProxyBroker<IGnssMeasurementCallback>(remote) {
    }
    int32_t ReportGnssMeasurementInfo(const GnssMeasurementInfo& data) override;
};
} // V2_0
} // Gnss
} // Location
} // HDI
} // OHOS
#endif // GNSS_MEASUREMENT_CALLBACK_TEST_H