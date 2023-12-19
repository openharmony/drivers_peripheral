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

void SensorClientInfo::SetPeriodCount(int32_t sensorId, int32_t periodCount){
    periodCountMap_[sensorId] = periodCount;
    curCountMap_[sensorId] = 0;
    std::string periodCountMap_Msg = "{";
    for (auto it = periodCountMap_.begin(); it != periodCountMap_.end(); ++it) {
        if (it != periodCountMap_.begin()) {
            periodCountMap_Msg +=", ";
        }
        periodCountMap_Msg += std::to_string(periodCountMap_[it]->first) + "->" +
                              std::to_string(periodCountMap_[it]->second);
    }
    periodCountMap_Msg += "}";
    std::string curCountMap_Msg = "{";
    for (auto it = curCountMap_.begin(); it != curCountMap_.end(); ++it) {
        if (it != curCountMap_.begin()) {
            curCountMap_Msg +=", ";
        }
        curCountMap_Msg += std::to_string(curCountMap_[it]->first) + "->" +
                              std::to_string(curCountMap_[it]->second);
    }
    curCountMap_Msg += "}";
    HDF_LOGI("%{public}s: enter the SetPeriodCount function, now periodCountMap_ is %{public}s, "+
             "curCountMap_ is %{public}s", __func__, serviceId, periodCountMap_Msg.c_str(), curCountMap_Msg.c_str());
}

bool SensorClientInfo::IsNeedReportData(int32_t sensorId) {
    if (periodCountMap_.find(sensorId) == periodCountMap_.end()) {
        return true;
    }
    curCountMap_[sensorId]++;
    std::string periodCountMap_Msg = "{";
    for (auto it = periodCountMap_.begin(); it != periodCountMap_.end(); ++it) {
        if (it != periodCountMap_.begin()) {
            periodCountMap_Msg +=", ";
        }
        periodCountMap_Msg += std::to_string(periodCountMap_[it]->first) + "->" +
                              std::to_string(periodCountMap_[it]->second);
    }
    periodCountMap_Msg += "}";
    std::string curCountMap_Msg = "{";
    for (auto it = curCountMap_.begin(); it != curCountMap_.end(); ++it) {
        if (it != curCountMap_.begin()) {
            curCountMap_Msg +=", ";
        }
        curCountMap_Msg += std::to_string(curCountMap_[it]->first) + "->" +
                           std::to_string(curCountMap_[it]->second);
    }
    curCountMap_Msg += "}";
    HDF_LOGI("%{public}s: enter the SetPeriodCount function, now periodCountMap_ is %{public}s, "+
             "curCountMap_ is %{public}s", __func__, serviceId, periodCountMap_Msg.c_str(), curCountMap_Msg.c_str());
    if (curCountMap_[sensorId] % periodCountMap_[sensorId] == 0) {
        curCountMap_[sensorId] = 0;
        return true;
    }
    return false;
}

} // V2_0
} // Sensor
} // HDI
} // OHOS