/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_SENSOR_V2_0_SENSORCALLBACKIMPLTEST_H
#define OHOS_HDI_SENSOR_V2_0_SENSORCALLBACKIMPLTEST_H

#include <hdf_base.h>
#include <securec.h>
#include "v2_0/isensor_callback.h"
#include "sensor_uhdf_log.h"
#include "osal_mem.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {

constexpr int32_t DATA_LEN = 256;

class SensorCallbackImplTest : public ISensorCallback {
public:
    virtual ~SensorCallbackImplTest() {}

    int32_t OnDataEvent(const HdfSensorEvents& event) override;
};
} // V2_0
} // Sensor
} // HDI
} // OHOS

#endif // OHOS_HDI_SENSOR_V2_0_SENSORCALLBACKIMPLTEST_H
