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

#include "dcameracreatestreams_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dstream_operator.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
const uint32_t DC_ENCODE_SIZE = 4;
const EncodeType encodeType[DC_ENCODE_SIZE] = {
    EncodeType::ENCODE_TYPE_NULL, EncodeType::ENCODE_TYPE_H264, EncodeType::ENCODE_TYPE_H265,
    EncodeType::ENCODE_TYPE_JPEG
};
const uint32_t DC_STREAMINTENT_SIZE = 6;
const StreamIntent streamIntentType[DC_STREAMINTENT_SIZE] = {
    StreamIntent::PREVIEW, StreamIntent::VIDEO, StreamIntent::STILL_CAPTURE, StreamIntent::POST_VIEW,
    StreamIntent::ANALYZE, StreamIntent::CUSTOM
};
}
void DcameraCreateStreamsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::vector<StreamInfo> infos;
    StreamInfo info;
    info.streamId_ = *(reinterpret_cast<const int*>(data));
    info.width_ = *(reinterpret_cast<const int*>(data));
    info.height_ = *(reinterpret_cast<const int*>(data));
    info.format_ = *(reinterpret_cast<const int*>(data));
    info.dataspace_ = *(reinterpret_cast<const int*>(data));
    info.intent_ = streamIntentType[data[0] % DC_STREAMINTENT_SIZE];
    info.tunneledMode_ = *(reinterpret_cast<const int*>(data)) % 2;
    info.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable());
    info.encodeType_ = encodeType[data[0] % DC_ENCODE_SIZE];
    infos.push_back(info);

    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DMetadataProcessor> dMetadataProcessor = std::make_shared<DMetadataProcessor>();
    dMetadataProcessor->InitDCameraAbility(sinkAbilityInfo);
    OHOS::sptr<DStreamOperator> dCameraStreamOperator(new (std::nothrow) DStreamOperator(dMetadataProcessor));

    dCameraStreamOperator->CreateStreams(infos);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraCreateStreamsFuzzTest(data, size);
    return 0;
}

