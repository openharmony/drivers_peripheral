/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "dstreamgetstreamattributes_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "dstream_operator.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
const uint8_t MAX_STRING_LENGTH = 255;

void DstreamGetStreamAttributesFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::vector<StreamAttribute> attributes;
    StreamAttribute attribute;
    attribute.streamId_ = fdp.ConsumeIntegral<int>();
    attribute.width_ = fdp.ConsumeIntegral<int>();
    attribute.height_ = fdp.ConsumeIntegral<int>();
    attribute.overrideFormat_ = fdp.ConsumeIntegral<int>();
    attribute.overrideDataspace_ = fdp.ConsumeIntegral<int>();
    attribute.producerUsage_ = fdp.ConsumeIntegral<int>();
    attribute.producerBufferCount_ = fdp.ConsumeIntegral<int>();
    attribute.maxBatchCaptureCount_ = fdp.ConsumeIntegral<int>();
    attribute.maxCaptureCount_ = fdp.ConsumeIntegral<int>();
    attributes.push_back(attribute);

    std::string sinkAbilityInfo(fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::shared_ptr<DMetadataProcessor> dMetadataProcessor = std::make_shared<DMetadataProcessor>();
    dMetadataProcessor->InitDCameraAbility(sinkAbilityInfo);
    OHOS::sptr<DStreamOperator> dCameraStreamOperator(new (std::nothrow) DStreamOperator(dMetadataProcessor));

    dCameraStreamOperator->GetStreamAttributes(attributes);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DstreamGetStreamAttributesFuzzTest(data, size);
    return 0;
}

