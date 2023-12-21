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

#include "sensor_callback_vdi.h"
#include "sensor_clients_manager.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V2_0 {

int32_t SensorCallbackVdi::OnDataEventVdi(const OHOS::HDI::Sensor::V1_1::HdfSensorEventsVdi& eventVdi)
{
    struct HdfSensorEvents event;
    int32_t ret;
    if (sensorCallback_ == nullptr) {
        HDF_LOGE("%{public}s sensorCallback_ is NULL", __func__);
        return HDF_FAILURE;
    }

    event.sensorId = eventVdi.sensorId;
    event.version = eventVdi.version;
    event.timestamp = eventVdi.timestamp;
    event.option = eventVdi.option;
    event.mode = eventVdi.mode;
    event.data = eventVdi.data;
    event.dataLen = eventVdi.dataLen;
    std::unordered_map<int, std::set<int>> sensorEnabled = SensorClientsManager::GetInstance()->GetSensorUsed();
    std::unordered_map<int, SensorClientInfo> client;
    if (!SensorClientsManager::GetInstance()->GetClients(HDF_TRADITIONAL_SENSOR_TYPE, client)) {
        HDF_LOGE("%{public}s groupId %{public}d is not used by anyone", __func__, HDF_TRADITIONAL_SENSOR_TYPE);
        return HDF_FAILURE;
    }
    sptr<ISensorCallback> callback;
    if (sensorEnabled.find(event.sensorId) == sensorEnabled.end()) {
        HDF_LOGE("%{public}s sensor %{public}d is not enabled by anyone", __func__, event.sensorId);
        return HDF_FAILURE;
    }
    for (auto it = sensorEnabled[event.sensorId].begin(); it != sensorEnabled[event.sensorId].end(); ++it) {
        sensorClientInfo_ = client[*it];
        callback = sensorClientInfo_.GetReportDataCb();
        if (callback == nullptr) {
            HDF_LOGE("%{public}s the callback of %{public}d is nullptr", __func__, *it);
            continue;
        }
        ret = callback->OnDataEvent(event);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s Sensor OnDataEvent failed, error code is %{public}d", __func__, ret);
            SensorClientsManager::GetInstance()->IsUpadateSensorState(event.sensorId, *it, false);
        }
    }
    return HDF_SUCCESS;
}

sptr<IRemoteObject> SensorCallbackVdi::HandleCallbackDeath()
{
    sptr<IRemoteObject> remote = OHOS::HDI::hdi_objcast<ISensorCallback>(sensorCallback_);

    return remote;
}
} // V2_0
} // Sensor
} // HDI
} // OHOS
