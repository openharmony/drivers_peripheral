/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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


#ifndef ENCODE_BUFFER_HELPER_FUZZ
#define ENCODE_BUFFER_HELPER_FUZZ

#include <map>
#include <list>
#include <set>
#include <fstream>
#include "log.h"
#include "v2_0/icodec_image.h"
#include "v1_2/display_composer_type.h"
#include "v1_2/display_buffer_type.h"
#include "v1_2/include/idisplay_buffer.h"

namespace OHOS::VDI::HEIF {
uint32_t ToUint32(const uint8_t* ptr);
class EncodeBufferHelper {
public:
    EncodeBufferHelper();
    ~EncodeBufferHelper();
    OHOS::sptr<OHOS::HDI::Base::NativeBuffer> CreateImgBuffer(uint8_t* data, size_t size);
    OHOS::HDI::Codec::Image::V2_0::SharedBuffer CreateSharedBuffer(uint8_t* data, size_t size);
private:
    struct PixelFileInfo {
        uint32_t displayWidth;
        uint32_t alignedWidth;
        uint32_t displayHeight;
        uint32_t alignedHeight;
        int32_t pixFmt;
    };
private:
    bool InitialRgbaData(BufferHandle* handle, PixelFileInfo& pixelInfo, uint8_t* data, size_t size);
private:
    OHOS::HDI::Display::Buffer::V1_2::IDisplayBuffer* bufferMgr_;
    std::set<int> allocatedFd_;
};
} // OHOS::VDI::HEIF

#endif // ENCODE_BUFFER_HELPER_FUZZ