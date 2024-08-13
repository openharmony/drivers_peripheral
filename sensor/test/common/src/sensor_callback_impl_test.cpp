/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <cmath>

#include "osal_mem.h"
#include "sensor_callback_impl_test.h"
#include "sensor_type.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {
int32_t SensorCallbackImplTest::OnDataEvent(const HdfSensorEvents& event)
{
    HDF_LOGI("%{public}s sensorId=%{public}d", __func__, event.sensorId);
    PrintData(event);
    return HDF_FAILURE;
}
} // V2_0
} // Sensor
} // HDI
} // OHOS
