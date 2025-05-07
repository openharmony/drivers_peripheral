/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "ipc_skeleton.h"
#include "audio_dfx_vdi.h"
#ifdef AUDIO_HITRACE_ENABLE
#include <hitrace_meter.h>
#endif
#ifdef AUDIO_HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#endif
#include "hisysevent.h"

using namespace OHOS::HiviewDFX;

#define HICOLLIE_TIMEOUT 8

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

void SetMaxWorkThreadNum(int32_t count)
{
    OHOS::IPCSkeleton::GetInstance().SetMaxWorkThreadNum(count);
}

int32_t AudioDfxSysEventStreamInfo(const char* name, const struct AudioSampleAttributes* attrs,
    const struct AudioDeviceDescriptor* desc)
{
    if (name == nullptr || attrs == nullptr || desc == nullptr) {
        AUDIO_FUNC_LOGE("invalid param");
        return HDF_ERR_INVALID_PARAM;
    }
    return HiSysEventWrite(HiSysEvent::Domain::HDF_AUDIO, "DRIVER_AUDIO_STREAM_EVENT",
        HiSysEvent::EventType::STATISTIC, "ADAPTER_NAME", name, "AUDIO_CATEGORY", attrs->type,
        "AUDIO_INPUT_TYPE", attrs->sourceType, "AUDIO_FORMAT", attrs->format, "SAMPLE_RATE", attrs->sampleRate,
        "CHANNEL_COUNT", attrs->channelCount, "AUDIO_PIN", desc->pins);
}

int32_t AudioDfxSysEventError(const char* errLog, int32_t code)
{
    return HiSysEventWrite(HiSysEvent::Domain::HDF_AUDIO, "DRIVER_AUDIO_ERROR_EVENT",
        HiSysEvent::EventType::STATISTIC, "ERROR_LOG", errLog, "ERROR_CODE", code);
}

struct timeval AudioDfxSysEventGetTimeStamp(void)
{
    struct timeval startTime;
    gettimeofday(&startTime, nullptr);
    return startTime;
}

int32_t AudioDfxSysEventOverTime(const char* log, struct timeval startTime, int timeThreshold)
{
    struct timeval endTime;
    gettimeofday(&endTime, nullptr);
    int32_t runTime = (int32_t)((endTime.tv_sec - startTime.tv_sec) * TIME_1000 +
        (endTime.tv_usec - startTime.tv_usec) / TIME_1000);
    if (runTime > (int64_t)timeThreshold) {
        AUDIO_FUNC_LOGE("%{public}s, ovet time [%{public}ld]", log, runTime);
        return HiSysEventWrite(HiSysEvent::Domain::HDF_AUDIO, "DRIVER_AUDIO_OVER_TIME_EVENT",
            HiSysEvent::EventType::STATISTIC, "LOG", log, "OVER_TIME", runTime);
    }
    return HDF_SUCCESS;
}