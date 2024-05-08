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

#include "dstreamcapture_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dstream_operator.h"
#include "v1_0/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
void DstreamCaptureFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t captureId = *(reinterpret_cast<const int*>(data));
    int32_t streamId = *(reinterpret_cast<const int*>(data));
    int32_t value = 2;
    std::string captureSetting(reinterpret_cast<const char*>(data), size);
    std::vector<int32_t> streamIds;
    streamIds.push_back(streamId);

    CaptureInfo info;
    info.streamIds_.assign(streamIds.begin(), streamIds.end());
    info.captureSetting_.assign(captureSetting.begin(), captureSetting.end());
    info.enableShutterCallback_ = data[0] % value;
    bool isStreaming = data[0] % value;
    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DMetadataProcessor> dMetadataProcessor = std::make_shared<DMetadataProcessor>();
    dMetadataProcessor->InitDCameraAbility(sinkAbilityInfo);
    OHOS::sptr<DStreamOperator> dCameraStreamOperator(new (std::nothrow) DStreamOperator(dMetadataProcessor));

    dCameraStreamOperator->Capture(captureId, info, isStreaming);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DstreamCaptureFuzzTest(data, size);
    return 0;
}

