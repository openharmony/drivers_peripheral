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

#include "thermal_hdf_timer.h"
#include <cerrno>
#include <thread>
#include <fcntl.h>
#include <unistd.h>
#include <hdf_base.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <linux/netlink.h>
#include "thermal_log.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_0 {
namespace {
const int32_t MS_PER_SECOND = 1000;
const std::string THERMAL_SIMULATION_TAG = "sim_tz";
}
ThermalHdfTimer::ThermalHdfTimer(const std::shared_ptr<ThermalSimulationNode> &node,
    const std::shared_ptr<ThermalZoneManager> &thermalZoneMgr)
{
    node_ = node;
    thermalZoneMgr_ = thermalZoneMgr;
    reportTime_ = 0;
}

ThermalHdfTimer::~ThermalHdfTimer()
{
    isRunning_ = false;
    if (callbackThread_ != nullptr && callbackThread_->joinable()) {
        callbackThread_->join();
    }
}

void ThermalHdfTimer::SetThermalEventCb(const sptr<IThermalCallback> &thermalCb)
{
    thermalCb_ = thermalCb;
}

void ThermalHdfTimer::SetSimluationFlag()
{
    auto baseConfigList = ThermalHdfConfig::GetInsance().GetBaseConfig()->GetBaseItem();
    if (baseConfigList.empty()) {
        THERMAL_HILOGE(COMP_HDI, "baseConfigList is empty");
        return;
    }
    auto baseIter = std::find(baseConfigList.begin(), baseConfigList.end(), THERMAL_SIMULATION_TAG);
    if (baseIter != baseConfigList.end()) {
        isSim_ = atoi(baseIter->value.c_str());
        THERMAL_HILOGI(COMP_HDI, "isSim value:%{public}d", isSim_);
    } else {
        THERMAL_HILOGI(COMP_HDI, "not found");
    }
}

void ThermalHdfTimer::SetSimFlag(int32_t flag)
{
    isSim_ = flag;
}

int32_t ThermalHdfTimer::GetSimluationFlag()
{
    return isSim_;
}

void ThermalHdfTimer::TimerProviderCallback()
{
    reportTime_ = reportTime_ + 1;
    ReportThermalData();
    ResetCount();
    return;
}

void ThermalHdfTimer::LoopingThreadEntry()
{
    while (isRunning_) {
        std::this_thread::sleep_for(std::chrono::seconds(thermalZoneMgr_->maxCd_ / MS_PER_SECOND));
        TimerProviderCallback();
    }
}

void ThermalHdfTimer::Run()
{
    callbackThread_ = std::make_unique<std::thread>(&ThermalHdfTimer::LoopingThreadEntry, this);
}

void ThermalHdfTimer::StartThread()
{
    Run();
}

int32_t ThermalHdfTimer::Init()
{
    thermalDfx_ = std::make_unique<ThermalDfx>();
    if (thermalDfx_ != nullptr) {
        thermalDfx_->Init();
    }
    StartThread();
    return HDF_SUCCESS;
}

void ThermalHdfTimer::ReportThermalData()
{
    if (thermalCb_ == nullptr) {
        THERMAL_HILOGE(COMP_HDI, "check thermalCb_ failed");
        return;
    }

    thermalZoneMgr_->ReportThermalZoneData(reportTime_, multipleList_);
    tzInfoEvent_ = thermalZoneMgr_->GetCallbackInfo();
    // callback thermal event
    thermalCb_->OnThermalDataEvent(tzInfoEvent_);
}

void ThermalHdfTimer::ResetCount()
{
    THERMAL_HILOGI(COMP_HDI, "multipleList_:%{public}zu", multipleList_.size());
    if (multipleList_.empty()) return;

    int32_t maxValue = *(std::max_element(multipleList_.begin(), multipleList_.end()));
    if (reportTime_ == maxValue) {
        THERMAL_HILOGI(COMP_HDI, "reportTime:%{public}d", reportTime_);
        reportTime_ = 0;
    }
    tzInfoEvent_.info.clear();
}

void ThermalHdfTimer::DumpSensorConfigInfo()
{
    auto sensorTypeMap = ThermalHdfConfig::GetInsance().GetSensorTypeMap();
    for (auto sensorIter : sensorTypeMap) {
        THERMAL_HILOGI(COMP_HDI, "groupName %{public}s, interval %{public}d, multiple %{public}d",
            sensorIter.first.c_str(), sensorIter.second->GetInterval(), sensorIter.second->multiple_);
        for (auto tzIter : sensorIter.second->GetXMLThermalZoneInfo()) {
            THERMAL_HILOGI(COMP_HDI, "type %{public}s, replace %{public}s", tzIter.type.c_str(),
                tzIter.replace.c_str());
        }
        for (auto tnIter : sensorIter.second->GetXMLThermalNodeInfo()) {
            THERMAL_HILOGI(COMP_HDI, "type %{public}s", tnIter.type.c_str());
        }
        for (auto dataIter : sensorIter.second->thermalDataList_) {
            THERMAL_HILOGI(COMP_HDI, "data type %{public}s", dataIter.type.c_str());
        }
    }
}
} // V1_0
} // Thermal
} // HDI
} // OHOS
