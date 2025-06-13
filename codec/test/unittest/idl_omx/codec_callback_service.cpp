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

#include "v4_0/codec_callback_service.h"
#include <hdf_base.h>

namespace OHOS {
namespace HDI {
namespace Codec {
namespace V4_0 {
int32_t CodecCallbackService::EventHandler(CodecEventType event, const EventInfo &info)
{
    (void)event;
    (void)info;
    return HDF_SUCCESS;
}

int32_t CodecCallbackService::EmptyBufferDone(int64_t appData, const OmxCodecBuffer& buffer)
{
    (void)appData;
    (void)buffer;
    return HDF_SUCCESS;
}

int32_t CodecCallbackService::FillBufferDone(int64_t appData, const OmxCodecBuffer& buffer)
{
    (void)appData;
    (void)buffer;
    return HDF_SUCCESS;
}
} // V4_0
} // Codec
} // HDI
} // OHOS
