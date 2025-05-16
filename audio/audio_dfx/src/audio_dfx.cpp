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

struct timeval AudioDfxSysEventGetTimeStamp(void)
{
    struct timeval startTime;
    gettimeofday(&startTime, nullptr);
    return startTime;
}

int32_t AudioDfxSysEventError(const char* desc, struct timeval startTime, int timeThreshold, int err)
{
    if (err != HDF_SUCCESS) {
        HiSysEventWrite(HiSysEvent::Domain::AUDIO, "HDF_AUDIO_ERROR_EVENT", HiSysEvent::EventType::FAULT,
            "ERROR_DESC", desc, "ERROR_CODE", err, "OVER_TIME", 0);
    }
    struct timeval endTime;
    gettimeofday(&endTime, nullptr);
    int32_t runTime = (int32_t)((endTime.tv_sec - startTime.tv_sec) * TIME_1000 +
        (endTime.tv_usec - startTime.tv_usec) / TIME_1000);
    if (runTime > timeThreshold) {
        AUDIO_FUNC_LOGE("%{public}s, ovet time [%{public}d]", desc, runTime);
        HiSysEventWrite(HiSysEvent::Domain::AUDIO, "HDF_AUDIO_ERROR_EVENT", HiSysEvent::EventType::FAULT,
            "ERROR_DESC", desc, "ERROR_CODE", err, "OVER_TIME", runTime);
    }
    return HDF_SUCCESS;
}
