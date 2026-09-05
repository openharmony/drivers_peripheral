/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "dcameraprovidernotifytrigger_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "constants.h"
#include "dcamera_provider.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
const uint8_t MAX_STRING_LENGTH = 255;

void FuzzNotifyWithJsonContent(FuzzedDataProvider &fdp)
{
    DHBase dhBase;
    dhBase.deviceId_ = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    dhBase.dhId_ = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    DCameraHDFEvent event;
    event.type_ = fdp.ConsumeIntegral<int32_t>();
    event.result_ = fdp.ConsumeIntegral<int32_t>();
    event.content_ = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    DCameraProvider::GetInstance()->Notify(dhBase, event);
}

void FuzzNotifyWithForceSwitch(FuzzedDataProvider &fdp)
{
    DHBase dhBase;
    dhBase.deviceId_ = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    dhBase.dhId_ = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    DCameraHDFEvent event;
    event.type_ = DCameraEventType::DCAMERE_FORCE_SWITCH;
    event.result_ = fdp.ConsumeIntegral<int32_t>();
    event.content_ = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    DCameraProvider::GetInstance()->Notify(dhBase, event);
}

void DcameraProviderNotifyTriggerFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    uint8_t route = fdp.ConsumeIntegral<uint8_t>() % 2;
    if (route == 0) {
        FuzzNotifyWithJsonContent(fdp);
    } else {
        FuzzNotifyWithForceSwitch(fdp);
    }
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DistributedHardware::DcameraProviderNotifyTriggerFuzzTest(data, size);
    return 0;
}
