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

#ifndef PERIPHERAL_GNSS_TEST_H
#define PERIPHERAL_GNSS_TEST_H

#include <gtest/gtest.h>
#include <v2_0/ignss_interface.h>
#include "gnss_measurement_callback_test.h"
#include "location_vendor_interface.h"
#include "iremote_object.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "location_vendor_interface.h"
#include "location_vendor_lib.h"

using OHOS::HDI::Location::Gnss::V2_0::IGnssCallback;
using OHOS::HDI::Location::Gnss::V2_0::IGnssInterface;
namespace OHOS {
namespace HDI {
namespace Location {
namespace Gnss {
namespace V2_0 {

class PeripheralGnssTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    sptr<GnssInterfaceImpl> gnssInstance_;
    sptr<IGnssMeasurementCallback> gnssMeasurementCallback_;
    sptr<IGnssCallback> gnssCallback_;
};
} // V2_0
} // Gnss
} // Location
} // HDI
} // OHOS
#endif // PERIPHERAL_GNSS_TEST_H