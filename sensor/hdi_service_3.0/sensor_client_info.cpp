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

#include "sensor_client_info.h"
#include "sensor_uhdf_log.h"

#define HDF_LOG_TAG client

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {

SensorClientInfo::SensorClientInfo()
{
}

SensorClientInfo::~SensorClientInfo()
{
    sensorConfigMap_.clear();
    periodCountMap_.clear();
    curCountMap_.clear();
}

void SensorClientInfo::SetReportDataCb(const sptr<V3_0::ISensorCallback> &callbackObj)
{
    callbackV3_0 = callbackObj;
}

void SensorClientInfo::PrintClientMapInfo(int32_t serviceId, SensorHandle sensorHandle)
{
    HDF_LOGD("%{public}s: service = %{public}d, sensorHandle = %{public}s, curCount/periodCount = "
             "%{public}d/%{public}d", __func__, serviceId, SENSOR_HANDLE_TO_C_STR(sensorHandle),
             curCountMap_[sensorHandle], periodCountMap_[sensorHandle]);
}

} // V3_0
} // Sensor
} // HDI
} // OHOS