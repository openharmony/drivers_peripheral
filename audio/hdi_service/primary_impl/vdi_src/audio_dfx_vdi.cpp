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

#include "audio_dfx_vdi.h"
#include <hitrace_meter.h>
#ifdef AUDIO_HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#endif

#define HICOLLIE_TIMEOUT 10

void HdfAudioStartTrace(const char* value, int valueLen)
{
    (void) valueLen;
    StartTrace(HITRACE_TAG_HDF, value);
}

void HdfAudioFinishTrace(void)
{
    FinishTrace(HITRACE_TAG_HDF);
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