/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "dcameradevicesetresultmode_fuzzer.h"

#include "dcamera_device.h"
#include "dcamera_host.h"
#include "v1_1/dcamera_types.h"
#include "v1_0/types.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {

const ResultCallbackMode VALID_RESULT_CALLBACK_MODES[] = {
    static_cast<ResultCallbackMode>(0),
    static_cast<ResultCallbackMode>(1),
};

void DcameraDeviceSetResultModeFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string dhId = fdp.ConsumeRandomLengthString();
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    ResultCallbackMode mode = fdp.PickValueInArray(VALID_RESULT_CALLBACK_MODES);
    std::string sinkAbilityInfo = fdp.ConsumeRandomLengthString();
    std::string srcAbilityInfo = fdp.ConsumeRandomLengthString();

    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    dcameraDevice->SetResultMode(mode);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraDeviceSetResultModeFuzzTest(data, size);
    return 0;
}