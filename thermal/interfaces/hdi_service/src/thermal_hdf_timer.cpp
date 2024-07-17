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

#include "thermal_hdf_timer.h"

#include <cerrno>
#include <fcntl.h>
#include <linux/netlink.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <thread>
#include <unistd.h>

#include "hdf_base.h"
#include "string_ex.h"
#include "thermal_dfx.h"
#include "thermal_log.h"
#include "thermal_hdf_utils.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
namespace {
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
    ThermalDfx::DestroyInstance();
}

void ThermalHdfTimer::SetSimluationFlag()
{
    auto baseConfigList = ThermalHdfConfig::GetInstance().GetBaseConfig()->GetBaseItem();
    if (baseConfigList.empty()) {
        THERMAL_HILOGE(COMP_HDI, "baseConfigList is empty");
        return;
    }
    auto baseIter = std::find(baseConfigList.begin(), baseConfigList.end(), THERMAL_SIMULATION_TAG);
    if (baseIter != baseConfigList.end()) {
        StrToInt(TrimStr(baseIter->value), isSim_);
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
    int32_t dfxInterval = static_cast<int32_t>(ThermalDfx::GetInstance().GetInterval());
    int32_t gcd = ThermalHdfUtils::GetMaxCommonDivisor(thermalZoneMgr_->GetMaxCd(), dfxInterval);
    if (dfxInterval == 0 || gcd == 0) {
        THERMAL_HILOGE(COMP_HDI, "LoopingThreadEntry error");
        return;
    }
    int32_t loopingTimes = 0;
    while (isRunning_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(gcd));
        loopingTimes++;
        int32_t dfxTask = loopingTimes % (dfxInterval / gcd);
        int32_t reportTask = loopingTimes % (thermalZoneMgr_->GetMaxCd() / gcd);
        if (dfxTask == 0) {
            ThermalDfx::GetInstance().DoWork();
        }
        if (reportTask == 0) {
            TimerProviderCallback();
        }
        // both dfxTask and reportTask execute, and reset loopingTimes
        if ((dfxTask == 0) && (reportTask == 0)) {
            loopingTimes = 0;
        }
    }
}

void ThermalHdfTimer::Run()
{
    callbackThread_ = std::make_unique<std::thread>([this] { this->LoopingThreadEntry(); });
}

void ThermalHdfTimer::StartThread()
{
    Run();
}

int32_t ThermalHdfTimer::Init()
{
    ThermalDfx::GetInstance().Init();
    StartThread();
    return HDF_SUCCESS;
}

void ThermalHdfTimer::ReportThermalData()
{
    thermalZoneMgr_->ReportThermalZoneData(reportTime_);
}

void ThermalHdfTimer::ResetCount()
{
    if (reportTime_ == thermalZoneMgr_->GetMaxReportTime()) {
        THERMAL_HILOGD(COMP_HDI, "reportTime:%{public}d", reportTime_);
        reportTime_ = 0;
    }
}
} // V1_1
} // Thermal
} // HDI
} // OHOS
