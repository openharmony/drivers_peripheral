/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "dcameranotify_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "dcamera_provider.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
const uint8_t MAX_STRING_LENGTH = 255;

void DcameraNotifyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string deviceId = "1";
    std::string dhId = "2";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;
    DCameraHDFEvent event;
    event.type_ = fdp.ConsumeIntegral<int>();
    event.result_ = fdp.ConsumeIntegral<int>();
    event.content_ = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);

    DCameraProvider::GetInstance()->Notify(dhBase, event);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraNotifyFuzzTest(data, size);
    return 0;
}

