/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HOST_STREAM_DATA_STRUCTURE_H
#define HOST_STREAM_DATA_STRUCTURE_H
#include <cstdint>
#include <functional>
#include "v1_0/types.h"
#include "ibuffer.h"
namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
using HostStreamInfo = struct {
    StreamIntent type_;
    int32_t streamId_;
    int32_t width_;
    int32_t height_;
    int32_t format_;
    uint64_t usage_;
    uint64_t bufferPoolId_;
    uint32_t bufferCount_;
    int32_t encodeType_;
    bool builed_ = false;
};

using BufferCb = std::function<void(std::shared_ptr<IBuffer>)>;
}
#endif

