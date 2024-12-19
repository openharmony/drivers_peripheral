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

#include "dcameraconfigurestreams_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "dcamera_provider.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
const uint32_t DC_ENCODE_SIZE = 4;
const DCEncodeType encodeType[DC_ENCODE_SIZE] = {
    DCEncodeType::ENCODE_TYPE_NULL, DCEncodeType::ENCODE_TYPE_H264, DCEncodeType::ENCODE_TYPE_H265,
    DCEncodeType::ENCODE_TYPE_JPEG
};
const uint32_t DC_STREAM_SIZE = 2;
const DCStreamType streamType[DC_STREAM_SIZE] = {
    DCStreamType::CONTINUOUS_FRAME, DCStreamType::SNAPSHOT_FRAME
};
const uint8_t MAX_STRING_LENGTH = 255;
}
void DcameraConfigureStreamsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string deviceId(fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH));
    std::string dhId(fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH));
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;
    std::vector<DCStreamInfo> streamInfos;
    DCStreamInfo streamInfo;
    streamInfo.streamId_ = fdp.ConsumeIntegral<int>();
    streamInfo.width_ = fdp.ConsumeIntegral<int>();
    streamInfo.height_ = fdp.ConsumeIntegral<int>();
    streamInfo.stride_ = fdp.ConsumeIntegral<int>();
    streamInfo.format_ = fdp.ConsumeIntegral<int>();
    streamInfo.dataspace_ = fdp.ConsumeIntegral<int>();
    streamInfo.encodeType_ = encodeType[data[0] % DC_ENCODE_SIZE];
    streamInfo.type_ = streamType[data[0] % DC_STREAM_SIZE];
    streamInfos.push_back(streamInfo);
    DCameraProvider::GetInstance()->ConfigureStreams(dhBase, streamInfos);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraConfigureStreamsFuzzTest(data, size);
    return 0;
}

