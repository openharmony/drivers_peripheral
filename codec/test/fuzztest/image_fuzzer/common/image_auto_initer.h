/*
 * Copyright (c) 2023 Shenzhen Kaihong DID Co., Ltd.
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

#ifndef IMAGE_AUTO_INITER
#define IMAGE_AUTO_INITER
#include "v1_0/icodec_image_jpeg.h"
namespace OHOS {
namespace Codec {
namespace Image {
class ImageAutoIniter {
public:
    ImageAutoIniter(OHOS::sptr<OHOS::HDI::Codec::Image::V1_0::ICodecImageJpeg> imageClient) : client_(imageClient)
    {
        if (client_) {
            client_->JpegInit();
        }
    }

    ~ImageAutoIniter()
    {
        if (client_) {
            client_->JpegDeInit();
            client_ = nullptr;
        }
    }

private:
    OHOS::sptr<OHOS::HDI::Codec::Image::V1_0::ICodecImageJpeg> client_;
};
}  // namespace Image
}  // namespace Codec
}  // namespace OHOS

#endif