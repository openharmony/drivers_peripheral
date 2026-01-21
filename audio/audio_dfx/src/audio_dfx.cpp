/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "audio_dfx.h"
#ifdef AUDIO_HITRACE_ENABLE
#include <hitrace_meter.h>
#endif
#ifdef AUDIO_HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#endif
#ifdef AUDIO_HISYSEVENT_ENABLE
#include "hisysevent.h"
#endif
#include <mutex>
#include <cstdint>
#include <iostream>
#include <fstream>

using namespace OHOS::HiviewDFX;

#define HICOLLIE_TIMEOUT 8

#ifdef AUDIO_RECLAIM_MEMORY_ENABLE
#define HICOLLIE_TIMEOUT_CALLBACK 120
#define INVALID_TIMER_ID (-1)
#define TIMER_CALLBACK "ReclaimMemoryCallback"
#define RECLAIM_FILEPAGE_STRING "3"
#endif

void HdfAudioStartTrace(const char* value, int valueLen)
{
    (void) valueLen;
#ifdef AUDIO_HITRACE_ENABLE
    StartTrace(HITRACE_TAG_HDF, value);
#else
    (void) value;
#endif
}

void HdfAudioFinishTrace(void)
{
#ifdef AUDIO_HITRACE_ENABLE
    FinishTrace(HITRACE_TAG_HDF);
#endif
}

int32_t SetTimer(const char* name)
{
    int32_t id = 0;
#ifdef AUDIO_HICOLLIE_ENABLE
    id = OHOS::HiviewDFX::XCollie::GetInstance().SetTimer(name, HICOLLIE_TIMEOUT, nullptr, nullptr,
        OHOS::HiviewDFX::XCOLLIE_FLAG_LOG | OHOS::HiviewDFX::XCOLLIE_FLAG_RECOVERY);
#else
    (void)name;
#endif
    return id;
}

void CancelTimer(int32_t id)
{
#ifdef AUDIO_HICOLLIE_ENABLE
    if (id != 0) {
        OHOS::HiviewDFX::XCollie::GetInstance().CancelTimer(id);
    }
#else
    (void)id;
#endif
}

struct timeval AudioDfxSysEventGetTimeStamp(void)
{
    struct timeval startTime;
    gettimeofday(&startTime, nullptr);
    return startTime;
}

int32_t AudioDfxSysEventError(const char* desc, struct timeval startTime, int timeThreshold, int err)
{
    if (err != HDF_SUCCESS) {
#ifdef AUDIO_HISYSEVENT_ENABLE
        HiSysEventWrite(HiSysEvent::Domain::AUDIO, "HDF_AUDIO_ERROR_EVENT", HiSysEvent::EventType::FAULT,
            "ERROR_DESC", desc, "ERROR_CODE", err, "OVER_TIME", 0);
#endif
    }
    struct timeval endTime;
    gettimeofday(&endTime, nullptr);
    int32_t runTime = (int32_t)((endTime.tv_sec - startTime.tv_sec) * TIME_1000 +
        (endTime.tv_usec - startTime.tv_usec) / TIME_1000);
    if (runTime > timeThreshold) {
        AUDIO_FUNC_LOGE("%{public}s, ovet time [%{public}d]", desc, runTime);
#ifdef AUDIO_HISYSEVENT_ENABLE
    if (runTime > timeThreshold * TIME_10) {
        HiSysEventWrite(HiSysEvent::Domain::AUDIO, "HDF_AUDIO_ERROR_EVENT", HiSysEvent::EventType::FAULT,
            "ERROR_DESC", desc, "ERROR_CODE", err, "OVER_TIME", runTime);
    }
#endif
    }
    return HDF_SUCCESS;
}

#ifdef AUDIO_RECLAIM_MEMORY_ENABLE
class Counter {
public:
    bool TryIncrement()
    {
        if (value_ == MAX_VALUE) {
            AUDIO_FUNC_LOGE("invalid increment");
            return false;
        }
        ++value_;
        return true;
    }

    bool TryDecrement()
    {
        if (value_ == 0) {
            AUDIO_FUNC_LOGE("invalid decrement");
            return false;
        }
        --value_;
        return true;
    }

    uint32_t Get() const
    {
        return value_;
    }
private:
    uint32_t value_{0};
    static constexpr uint32_t MAX_VALUE = UINT32_MAX;
};

Counter g_counter;
std::mutex g_mtx;
int32_t g_TimerId = INVALID_TIMER_ID;

void AudioXClollieCallback(void *param)
{
    std::lock_guard<std::mutex> lock(g_mtx);
    g_TimerId = INVALID_TIMER_ID;
    if (g_counter.Get() != 0) {
        return;
    }
    std::string path = "/proc/" + std::tostring(getpid()) + "/reclaim";
    std::string content = RECLAIM_FILEPAGE_STRING;
    std::ofstream outfile(path);
    if (outfile.is_open()) {
        outfile << countent;
        outfile.close();
        AUDIO_FUNC_LOGI("reclaim memory");
    } else {
        AUDIO_FUNC_LOGW("can't open file");
    }
}

int32_t SetCallbackTimer()
{
    int32_t id = INVALID_TIMER_ID;
#ifdef AUDIO_HICOLLIE_ENABLE
    id = OHOS::HiviewDFX::XCollie::GetInstance().SetTimer(TIMER_CALLBACK, HICOLLIE_TIMEOUT_CALLBACK, AudioXClollieCallback, nullptr,
        OHOS::HiviewDFX::XCOLLIE_FLAG_NOOP);
#endif
    return id;
}

void IncreaseCounter()
{
    std::lock_guard<std::mutex> lock(g_mtx);
    g_counter.TryIncrement();
    if (g_TimerId > 0) {
        CancelTimer(g_TimerId);
        g_TimerId = INVALID_TIMER_ID;
    }
}

void DecreaseCounter()
{
    std::lock_guard<std::mutex> lock(g_mtx);
    if (g_counter.TryDecrement() && (g_counter.Get() == 0)) {
        if (g_TimerId > 0) {
            CancelTimer(g_TimerId);
        }
        g_TimerId = SetCallbackTimer();
    }
}
#endif