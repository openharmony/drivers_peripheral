/*
 * Copyright 2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "codec_hdi_callback.h"
#include <hdf_log.h>
CodecHdiCallback::CodecHdiCallback(std::shared_ptr<ICodecHdiCallBackBase> codecHdi)
{
    codecHdi_ = codecHdi;
}

int32_t CodecHdiCallback::EventHandler(OHOS::HDI::Codec::V4_0::CodecEventType event,
    const OHOS::HDI::Codec::V4_0::EventInfo &info)
{
    if (codecHdi_) {
        codecHdi_->EventHandler(event, info);
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiCallback::EmptyBufferDone(int64_t appData, const OHOS::HDI::Codec::V4_0::OmxCodecBuffer &buffer)
{
    if (codecHdi_) {
        codecHdi_->OnEmptyBufferDone(buffer);
    }
    return HDF_SUCCESS;
}

int32_t CodecHdiCallback::FillBufferDone(int64_t appData, const OHOS::HDI::Codec::V4_0::OmxCodecBuffer &buffer)
{
    if (codecHdi_) {
        codecHdi_->OnFillBufferDone(buffer);
    }
    return HDF_SUCCESS;
}
