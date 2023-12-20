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

void SensorClientInfo::PrintLog()
{
    std::string sensorConfigMap_Msg = "{";
    for (auto it = sensorConfigMap_.begin(); it != sensorConfigMap_.end(); ++it) {
        if (it != sensorConfigMap_.begin()) {
            sensorConfigMap_Msg +=", ";
        }
        sensorConfigMap_Msg += std::to_string(it->first) + "->{" +
            std::to_string(it->second.samplingInterval) + "," +std::to_string(it->second.reportInterval) + "}";
    }
    sensorConfigMap_Msg += "}";
    std::string curCountMap_Msg = "{";
    for (auto it = curCountMap_.begin(); it != curCountMap_.end(); ++it) {
        if (it != curCountMap_.begin()) {
            curCountMap_Msg +=", ";
        }
        curCountMap_Msg += std::to_string(it->first) + "->" +
                           std::to_string(it->second);
    }
    curCountMap_Msg += "}";
    HDF_LOGI("%{public}s: enter the SetPeriodCount function, now sensorConfigMap_ is %{public}s, "
             "curCountMap_ is %{public}s", __func__, serviceId, sensorConfigMap_Msg.c_str(), curCountMap_Msg.c_str());
}

} // V2_0
} // Sensor
} // HDI
} // OHOS