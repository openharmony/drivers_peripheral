/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CODECJPEGCALLBACKSERVICE_H
#define CODECJPEGCALLBACKSERVICE_H

#include "v1_0/icodec_image_callback.h"
#include "jpeg_decoder.h"
class CodecJpegCallbackService : public OHOS::HDI::Codec::Image::V1_0::ICodecImageCallback {
public:
    CodecJpegCallbackService(std::shared_ptr<JpegDecoder> decoder);

    virtual ~CodecJpegCallbackService(){};

    int32_t OnImageEvent(int32_t error) override;

private:
    std::shared_ptr<JpegDecoder> decoder_;
};
#endif // CODECJPEGCALLBACKSERVICE_H
