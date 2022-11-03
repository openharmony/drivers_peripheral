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
const int32_t ERR_INVALID_FD = -1;
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
        THERMAL_HILOGD(COMP_HDI, "isSim value:%{public}d", isSim_);
    } else {
        THERMAL_HILOGD(COMP_HDI, "not found");
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

int32_t ThermalHdfTimer::CreateProviderFd()
{
    timerFd_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (timerFd_ == ERR_INVALID_FD) {
        THERMAL_HILOGE(COMP_HDI, "epoll create failed, epFd_ is invalid");
        return HDF_ERR_INVALID_PARAM;
    }

    THERMAL_HILOGD(COMP_HDI, "interval %{public}d", thermalZoneMgr_->maxCd_);
    SetTimerInterval(thermalZoneMgr_->maxCd_, timerFd_);
    fcntl(timerFd_, F_SETFL, O_NONBLOCK);
    callbackHandler_.insert(std::make_pair(timerFd_, &ThermalHdfTimer::TimerProviderCallback));
    if (RegisterCallback(timerFd_, EVENT_TIMER_FD, epFd_)) {
        THERMAL_HILOGD(COMP_HDI, "register Timer event failed");
    }

    THERMAL_HILOGD(COMP_HDI, "return");
    return HDF_SUCCESS;
}

int32_t ThermalHdfTimer::RegisterCallback(const int32_t fd, const EventType et, int32_t epfd)
{
    struct epoll_event ev;

    ev.events = EPOLLIN;
    if (et == EVENT_TIMER_FD) {
        ev.events |= EPOLLWAKEUP;
    }
    THERMAL_HILOGD(COMP_HDI, "%{public}d, %{public}d", epfd, fd);
    ev.data.ptr = reinterpret_cast<void*>(this);
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == HDF_FAILURE) {
        THERMAL_HILOGE(COMP_HDI, "epoll_ctl failed, error num =%{public}d",
            errno);
        return HDF_FAILURE;
    }
    THERMAL_HILOGD(COMP_HDI, "return");
    return HDF_SUCCESS;
}

void ThermalHdfTimer::TimerProviderCallback(void *service)
{
    unsigned long long timers;

    if (read(timerFd_, &timers, sizeof(timers)) == -1) {
        THERMAL_HILOGE(COMP_HDI, "read timerFd_ failed");
        return;
    }

    reportTime_ = reportTime_ + 1;
    ReportThermalData();
    ResetCount();
    return;
}

void ThermalHdfTimer::SetTimerInterval(int32_t interval, int32_t timerfd)
{
    struct itimerspec itval;

    if (timerfd == ERR_INVALID_FD) {
        return;
    }

    timerInterval_ = interval;

    if (interval < 0) {
        interval = 0;
    }

    itval.it_interval.tv_sec = interval / MS_PER_SECOND;
    itval.it_interval.tv_nsec = 0;
    itval.it_value.tv_sec = interval / MS_PER_SECOND;
    itval.it_value.tv_nsec = 0;
    if (timerfd_settime(timerfd, 0, &itval, nullptr) == -1) {
        THERMAL_HILOGE(COMP_HDI, "timer failed\n");
    }
    THERMAL_HILOGD(COMP_HDI, "return");
}

int32_t ThermalHdfTimer::InitProviderTimer()
{
    int32_t ret;
    epFd_ = epoll_create1(EPOLL_CLOEXEC);

    ret = CreateProviderFd();
    if (ret != HDF_SUCCESS) {
        THERMAL_HILOGE(COMP_HDI, "failed to create polling fd");
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t ThermalHdfTimer::LoopingThreadEntry(void *arg, int32_t epfd)
{
    int32_t nevents = 0;
    size_t eventct = callbackHandler_.size();
    struct epoll_event events[eventct];
    THERMAL_HILOGD(COMP_HDI, "%{public}d, %{public}zu", epfd, eventct);
    while (true) {
        nevents = epoll_wait(epfd, events, eventct, -1);
        if (nevents == -1) {
            continue;
        }
        for (int32_t n = 0; n < nevents; ++n) {
            if (events[n].data.ptr) {
                ThermalHdfTimer *func = const_cast<ThermalHdfTimer *>(this);
                (callbackHandler_.find(events[n].data.fd)->second)(func, arg);
            }
        }
    }
}

void ThermalHdfTimer::Run(void *service, int32_t epfd)
{
    std::make_unique<std::thread>(&ThermalHdfTimer::LoopingThreadEntry, this, service, epfd)->detach();
}

void ThermalHdfTimer::StartThread(void *service)
{
    int32_t ret = InitProviderTimer();
    if (ret != HDF_SUCCESS) {
        THERMAL_HILOGE(COMP_HDI, "init Timer failed, ret: %{public}d", ret);
        return;
    }
    Run(service, epFd_);
}

int32_t ThermalHdfTimer::Init()
{
    StartThread(this);
    return HDF_SUCCESS;
}

void ThermalHdfTimer::ReportThermalData()
{
    if (thermalCb_ == nullptr) {
        THERMAL_HILOGE(COMP_HDI, "check thermalCb_ failed");
        return;
    }

    thermalZoneMgr_->ReportThermalZoneData(reportTime_, multipleList_);
    tzInfoEvent_ = thermalZoneMgr_->tzInfoAcaualEvent_;
    // callback thermal event
    thermalCb_->OnThermalDataEvent(tzInfoEvent_);
}

void ThermalHdfTimer::ResetCount()
{
    if (multipleList_.empty()) return;

    int32_t maxValue = *(std::max_element(multipleList_.begin(), multipleList_.end()));
    if (reportTime_ == maxValue) {
        reportTime_ = 0;
    }
    tzInfoEvent_.info.clear();
}

void ThermalHdfTimer::DumpSensorConfigInfo()
{
    auto sensorTypeMap = ThermalHdfConfig::GetInsance().GetSensorTypeMap();
    for (auto sensorIter : sensorTypeMap) {
        THERMAL_HILOGD(COMP_HDI, "groupName %{public}s, interval %{public}d, multiple %{public}d",
            sensorIter.first.c_str(), sensorIter.second->GetInterval(), sensorIter.second->multiple_);
        for (auto tzIter : sensorIter.second->GetXMLThermalZoneInfo()) {
            THERMAL_HILOGD(COMP_HDI, "type %{public}s, replace %{public}s", tzIter.type.c_str(),
                tzIter.replace.c_str());
        }
        for (auto tnIter : sensorIter.second->GetXMLThermalNodeInfo()) {
            THERMAL_HILOGD(COMP_HDI, "type %{public}s, path %{public}s", tnIter.type.c_str(),
                tnIter.path.c_str());
        }
        for (auto dataIter : sensorIter.second->thermalDataList_) {
            THERMAL_HILOGD(COMP_HDI, "data type %{public}s, data temp path %{public}s", dataIter.type.c_str(),
                dataIter.tempPath.c_str());
        }
    }
}
} // V1_0
} // Thermal
} // HDI
} // OHOS
