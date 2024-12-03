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

#include "audio_dfx_util.h"
#ifdef AUDIO_HITRACE_ENABLE
#include <hitrace_meter.h>
#endif
#ifdef AUDIO_HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#endif
#include "audio_uhdf_log.h"

#define HICOLLIE_TIMEOUT 8
#define TIME_1000 1000

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

void CheckOverTime(struct timeval startTimeStamp, int64_t overTime, const char* logStr)
{
    struct timeval stopTimeStamp = {0};
    gettimeofday(&stopTimeStamp, nullptr);
    int32_t runTime = (int32_t)((stopTimeStamp.tv_sec - startTimeStamp.tv_sec) * TIME_1000 +
        (stopTimeStamp.tv_usec - startTimeStamp.tv_usec) / TIME_1000);
    if (runTime > overTime) {
        HDF_LOGW("run %{public}s over time, [%{public}d]ms", logStr, runTime);
    }
}