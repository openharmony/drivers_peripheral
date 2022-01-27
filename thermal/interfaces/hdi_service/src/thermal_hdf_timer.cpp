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
#include <hdf_log.h>
#include <hdf_base.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <linux/netlink.h>

namespace hdi {
namespace thermal {
namespace v1_0 {
namespace {
const int ERR_INVALID_FD = -1;
const int32_t MS_PER_SECOND = 1000;
const std::string POLLING_V1 = "v1";
const std::string POLLING_V2 = "v2";
}
ThermalHdfTimer::ThermalHdfTimer(const std::shared_ptr<ThermalSimulationNode> &node,
    const sptr<IThermalCallback> &theramalCb) : node_(node), theramalCb_(theramalCb)
{
}

int32_t ThermalHdfTimer::CreateProviderFd()
{
    HDF_LOGI("%{public}s enter", __func__);
    timerFd_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (timerFd_ == ERR_INVALID_FD) {
        HDF_LOGE("%{public}s epoll create failed, epFd_ is invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    auto intervalMap = ThermalHdfConfig::GetInsance().GetIntervalMap();
    auto v2 = intervalMap.find(POLLING_V2);
    if (v2 != intervalMap.end()) {
        int thermalPollingV2 = v2->second;
        HDF_LOGI("%{public}s: %{public}d", __func__, thermalPollingV2);
        SetTimerInterval(thermalPollingV2, timerFd_);
        fcntl(timerFd_, F_SETFL, O_NONBLOCK);
        callbackHandler_.insert(std::make_pair(timerFd_, &ThermalHdfTimer::TimerProviderCallback));
        if (RegisterCallback(timerFd_, EVENT_TIMER_FD, epFd_)) {
            HDF_LOGI("%{public}s register Timer event failed", __func__);
        }
    }

    HDF_LOGI("%{public}s return", __func__);
    return HDF_SUCCESS;
}

int32_t ThermalHdfTimer::RegisterCallback(const int fd, const EventType et, int32_t epfd)
{
    HDF_LOGI("%{public}s enter", __func__);
    struct epoll_event ev;

    ev.events = EPOLLIN;
    if (et == EVENT_TIMER_FD) {
        ev.events |= EPOLLWAKEUP;
    }
    HDF_LOGI("%{public}d, %{public}d", epfd, fd);
    ev.data.ptr = reinterpret_cast<void*>(this);
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == HDF_FAILURE) {
        HDF_LOGE("%{public}s: epoll_ctl failed, error num =%{public}d",
            __func__, errno);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s return", __func__);
    return HDF_SUCCESS;
}

void ThermalHdfTimer::TimerProviderCallback(void *service)
{
    HDF_LOGI("%{public}s enter", __func__);
    unsigned long long timers;

    if (read(timerFd_, &timers, sizeof(timers)) == -1) {
        HDF_LOGE("%{public}s read timerFd_ failed", __func__);
        return;
    }

    Notify();
    return;
}

void ThermalHdfTimer::SetTimerInterval(int interval, int32_t timerfd)
{
    HDF_LOGI("%{public}s enter, start SetTimerInterval: %{public}d", __func__, timerfd);
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
        HDF_LOGE("%{public}s: timer failed\n", __func__);
    }
    HDF_LOGI("return");
}

int32_t ThermalHdfTimer::InitProviderTimer()
{
    HDF_LOGI("%{public}s:  Enter", __func__);
    int32_t ret = -1;
    epFd_ = epoll_create1(EPOLL_CLOEXEC);

    ret = CreateProviderFd();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed to create polling fd", __func__);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t ThermalHdfTimer::LoopingThreadEntry(void *arg, int32_t epfd)
{
    int nevents = 0;
    size_t eventct = callbackHandler_.size();
    struct epoll_event events[eventct];
    HDF_LOGI("%{public}s: %{public}d, %{public}zu", __func__, epfd, eventct);
    while (true) {
        nevents = epoll_wait(epfd, events, eventct, -1);
        if (nevents == -1) {
            continue;
        }
        for (int n = 0; n < nevents; ++n) {
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
    HDF_LOGI("%{public}s: Enter", __func__);
    int ret = -1;
    ret = InitProviderTimer();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s init Timer failed, ret: %{public}d", __func__, ret);
        return;
    }
    Run(service, epFd_);
    HDF_LOGI("return");
}

int32_t ThermalHdfTimer::Init()
{
    HDF_LOGI("%{public}s: Enter", __func__);
    StartThread(this);
    return HDF_SUCCESS;
}

void ThermalHdfTimer::Notify()
{
    UpdatePollingInfo();
    if (theramalCb_ == nullptr) {
        HDF_LOGE("%{public}s: check theramalCb_ failed", __func__);
        return;
    } else {
        HDF_LOGI("%{public}s: enter", __func__);
        for (auto item = tzInfoEventV2_.info.begin(); item != tzInfoEventV2_.info.end(); item++) {
            HDF_LOGI("%{public}s: type: %{public}s", __func__, item->type.c_str());
            HDF_LOGI("%{public}s: temp: %{public}d", __func__, item->temp);
        }
        theramalCb_->OnThermalDataEvent(tzInfoEventV2_);
    }
    tzInfoEventV2_.info.clear();
    tzInfoEventV2_.info.clear();
}

void ThermalHdfTimer::UpdateTzInfo(const std::string &pollingName, HdfThermalCallbackInfo& infoEvent)
{
    HDF_LOGI("%{public}s: pollingName: %{public}s", __func__, pollingName.c_str());
    HdfThermalCallbackInfo tzInfoEvent;
    tzInfoEvent.info = node_->GetTzInfoList();
    HDF_LOGI("%{public}s: thermal zone event size:%{public}zu", __func__, tzInfoEvent.info.size());
    ThermalHdfConfig::ThermalTypeMap sensorTypeMap = ThermalHdfConfig::GetInsance().GetSensorTypeMap();
    auto pollingIter = sensorTypeMap.find(pollingName);
    if (pollingIter != sensorTypeMap.end()) {
        auto tzInfo = pollingIter->second->GetXMLThermalZoneInfo();
        auto tnInfo = pollingIter->second->GetXMLThermalNodeInfo();
        for (auto item = tzInfoEvent.info.begin(); item != tzInfoEvent.info.end(); item++) {
            HDF_LOGI("%{public}s: type: %{public}s", __func__, item->type.c_str());
            HDF_LOGI("%{public}s: temp: %{public}d", __func__, item->temp);
            CompareTzInfo(tzInfo, *item, infoEvent);
            CompareTnInfo(tnInfo, *item, infoEvent);
        }
    }
}

void ThermalHdfTimer::CompareTzInfo(const std::vector<XMLThermalZoneInfo> &tzInfoList, const ThermalZoneInfo &tzInfo,
    HdfThermalCallbackInfo& infoEvent)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (tzInfoList.empty()) {
        return;
    }
    ThermalZoneInfo info;
    for (auto iter = tzInfoList.begin(); iter != tzInfoList.end(); iter++) {
        HDF_LOGI("%{public}s: type: %{public}s", __func__, tzInfo.type.c_str());
        if (iter->isReplace) {
            if (tzInfo.type.find(iter->type) != std::string::npos) {
                info.temp = tzInfo.temp;
                info.type = iter->replace;
                infoEvent.info.push_back(info);
            }
        } else {
            if (tzInfo.type.find(iter->type) != std::string::npos) {
                info.temp = tzInfo.temp;
                info.type = iter->type;
                infoEvent.info.push_back(info);
            }
        }
    }
}

void ThermalHdfTimer::CompareTnInfo(const std::vector<XMLThermalNodeInfo> &tnInfoList, const ThermalZoneInfo &tzInfo,
    HdfThermalCallbackInfo& infoEvent)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (tnInfoList.empty()) {
        return;
    }
    ThermalZoneInfo info;
    for (auto iter = tnInfoList.begin(); iter != tnInfoList.end(); iter++) {
        HDF_LOGI("%{public}s: type: %{public}s", __func__, tzInfo.type.c_str());
        if (tzInfo.type.find(iter->type) != std::string::npos) {
            info.temp = tzInfo.temp;
            info.type = iter->type;
            infoEvent.info.push_back(info);
        }
    }
}

void ThermalHdfTimer::UpdatePollingInfo()
{
    int32_t ret = -1;
    ret = node_->ParserSimulationNode();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to parser simulation thermal zone info. ret: %{public}d", __func__, ret);
        return;
    }
    UpdateTzInfo(POLLING_V1, tzInfoEventV1_);
    UpdateTzInfo(POLLING_V2, tzInfoEventV2_);
}
} // v1_0
} // thermal
} // hdi