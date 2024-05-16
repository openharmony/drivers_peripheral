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

#include "dstreamchangetoofflinestream_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dstream_operator.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
class MockDStreamOperatorCallback : public IStreamOperatorCallback {
public:
    MockDStreamOperatorCallback() = default;

    virtual ~MockDStreamOperatorCallback() = default;

    int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds) override
    {
        return 0;
    }

    int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos) override
    {
        return 0;
    }

    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos) override
    {
        return 0;
    }

    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override
    {
        return 0;
    }
};
void DstreamChangeToOfflineStreamFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t streamId = *(reinterpret_cast<const int*>(data));
    std::vector<int32_t> streamIds;
    streamIds.push_back(streamId);
    sptr<IStreamOperatorCallback> callbackObj(new (std::nothrow) MockDStreamOperatorCallback());
    sptr<IOfflineStreamOperator> offlineOperator = nullptr;

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DMetadataProcessor> dMetadataProcessor = std::make_shared<DMetadataProcessor>();
    dMetadataProcessor->InitDCameraAbility(sinkAbilityInfo);
    OHOS::sptr<DStreamOperator> dCameraStreamOperator(new (std::nothrow) DStreamOperator(dMetadataProcessor));

    dCameraStreamOperator->ChangeToOfflineStream(streamIds, callbackObj, offlineOperator);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DstreamChangeToOfflineStreamFuzzTest(data, size);
    return 0;
}

