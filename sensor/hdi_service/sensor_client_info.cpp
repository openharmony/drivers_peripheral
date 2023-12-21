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
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {

SensorClientInfo::SensorClientInfo()
{
}

SensorClientInfo::~SensorClientInfo()
{
}

void SensorClientInfo::SetReportDataCb(const sptr<ISensorCallback> &callbackObj)
{
    pollCallback_ = callbackObj;
}

sptr<ISensorCallback> SensorClientInfo::GetReportDataCb()
{
    return pollCallback_;
}

bool SensorClientInfo::IsNotNeedReportData(int32_t sensorId)
{
    if (sensorConfigMap_.find(sensorId) == sensorConfigMap_.end()) {
        return false;
    }
    curCountMap_[sensorId]++;
    int64_t samplingInterval;
    int64_t reportInterval;
    OHOS::HDI::Sensor::V2_0::SensorClientsManager::GetInstance()->SetSensorBestConfig(sensorId, samplingInterval, reportInterval);
    int32_t periodCount = sensorConfigMap_[sensorId].reportInterval / reportInterval;
    PrintLog();
    if (curCountMap_[sensorId] >= periodCount) {
        curCountMap_[sensorId] = 0;
        return false;
    }
    return true;
}

} // V2_0
} // Sensor
} // HDI
} // OHOS