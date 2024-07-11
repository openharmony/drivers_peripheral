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

#ifndef THERMAL_HDF_TIMER_H
#define THERMAL_HDF_TIMER_H

#include <atomic>
#include <map>
#include <thread>
#include "thermal_hdf_config.h"
#include "thermal_simulation_node.h"
#include "thermal_zone_manager.h"
#include "v1_1/ithermal_callback.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
enum EventType {
    EVENT_UEVENT_FD,
    EVENT_TIMER_FD,
};
class ThermalHdfTimer {
public:
    using Callback = std::function<void(ThermalHdfTimer*, void*)>;

    ThermalHdfTimer(const std::shared_ptr<ThermalSimulationNode> &node,
        const std::shared_ptr<ThermalZoneManager> &thermalZoneMgr);
    ~ThermalHdfTimer();

    int32_t Init();
    void ReportThermalData();
    void LoopingThreadEntry();
    void Run();
    void StartThread();
    void ResetCount();
    void SetSimluationFlag();
    int32_t GetSimluationFlag();
    void SetSimFlag(int32_t flag);
    void DumpSensorConfigInfo();
private:
    void TimerProviderCallback();
    int32_t CreateProviderFd();

    std::map<int32_t, Callback> callbackHandler_;
    std::shared_ptr<ThermalSimulationNode> node_;
    std::shared_ptr<ThermalZoneManager> thermalZoneMgr_;
    HdfThermalCallbackInfo tzInfoEventV1_;
    HdfThermalCallbackInfo tzInfoEventV2_;
    HdfThermalCallbackInfo tzInfoEvent_;
    std::vector<int32_t> multipleList_;
    int32_t reportTime_;
    int32_t isSim_ = 0;
    std::atomic_bool isRunning_ {true};
    std::unique_ptr<std::thread> callbackThread_ {nullptr};
};
} // V1_1
} // Thermal
} // HDI
} // OHOS
#endif // THERMAL_HDF_TIMER_H