/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "codeccallback_fuzzer.h"
#include <hdf_base.h>

namespace OHOS {
namespace Codec {
int32_t CodecCallbackFuzz::EventHandler(OHOS::HDI::Codec::V4_0::CodecEventType event,
    const OHOS::HDI::Codec::V4_0::EventInfo &info)
{
    (void)event;
    (void)info;
    return HDF_SUCCESS;
}

int32_t CodecCallbackFuzz::EmptyBufferDone(int64_t appData, const OHOS::HDI::Codec::V4_0::OmxCodecBuffer &buffer)
{
    (void)appData;
    (void)buffer;
    return HDF_SUCCESS;
}

int32_t CodecCallbackFuzz::FillBufferDone(int64_t appData, const OHOS::HDI::Codec::V4_0::OmxCodecBuffer &buffer)
{
    (void)appData;
    (void)buffer;
    return HDF_SUCCESS;
}
} // namespace Codec
} // namespace OHOS
