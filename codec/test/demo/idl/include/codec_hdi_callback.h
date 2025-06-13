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

#ifndef CODEC_HDI_CALLBACK_H
#define CODEC_HDI_CALLBACK_H
#include "icodec_hdi_callback_base.h"
#include "v4_0/icodec_callback.h"
class CodecHdiCallback : public OHOS::HDI::Codec::V4_0::ICodecCallback {
public:
    CodecHdiCallback(std::shared_ptr<ICodecHdiCallBackBase> codecHdi);
    virtual ~CodecHdiCallback() = default;

    int32_t EventHandler(OHOS::HDI::Codec::V4_0::CodecEventType event,
        const OHOS::HDI::Codec::V4_0::EventInfo &info) override;

    int32_t EmptyBufferDone(int64_t appData, const OHOS::HDI::Codec::V4_0::OmxCodecBuffer &buffer) override;

    int32_t FillBufferDone(int64_t appData, const OHOS::HDI::Codec::V4_0::OmxCodecBuffer &buffer) override;

private:
    std::shared_ptr<ICodecHdiCallBackBase> codecHdi_;
};
#endif  // CODEC_HDI_CALLBACK_H