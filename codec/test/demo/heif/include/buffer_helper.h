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

#ifndef OHOS_HDI_CODEC_IMAGE_V2_0_BUFFER_HELPER
#define OHOS_HDI_CODEC_IMAGE_V2_0_BUFFER_HELPER

#include <map>
#include <list>
#include <set>
#include <fstream>
#include <securec.h>
#include "log.h"
#include "v2_0/icodec_image.h"
#include "v1_2/display_composer_type.h"
#include "v1_2/display_buffer_type.h"
#include "v1_2/include/idisplay_buffer.h"

namespace OHOS::VDI::HEIF {
class BufferHelper {
public:
    BufferHelper();
    ~BufferHelper();
    OHOS::sptr<OHOS::HDI::Base::NativeBuffer> CreateImgBuffer(const std::string& imageFile);
    OHOS::HDI::Codec::Image::V2_0::SharedBuffer CreateSharedBuffer(
        std::map<OHOS::HDI::Codec::Image::V2_0::PropertyType, std::string>& metaInfo);
    OHOS::HDI::Codec::Image::V2_0::SharedBuffer CreateSharedBuffer(const std::string& metaFile);
    void DumpBuffer(const std::string& filePath, const OHOS::HDI::Codec::Image::V2_0::SharedBuffer& buffer);
private:
    struct PixelFileInfo {
        uint32_t displayWidth;
        uint32_t alignedWidth;
        uint32_t displayHeight;
        uint32_t alignedHeight;
        uint32_t pixFmt;
    };
private:
    static bool ExtractPixelInfoFromFilePath(const std::string& filePath, PixelFileInfo& pixelInfo);
    static uint32_t GetPixelFmtFromFileSuffix(const std::string& imageFile);
    bool CopyYuvData(BufferHandle *handle, std::ifstream &ifs, PixelFileInfo& pixelInfo);
    bool CopyRgbaData(BufferHandle *handle, std::ifstream &ifs, PixelFileInfo& pixelInfo);
private:
    OHOS::HDI::Display::Buffer::V1_2::IDisplayBuffer* bufferMgr_;
    std::set<int> allocatedFd_;
};

class ByteWriter {
public:
    ByteWriter() = default;
    ~ByteWriter();
    template <typename T>
    bool AddData(OHOS::HDI::Codec::Image::V2_0::PropertyType key, T& value)
    {
        std::size_t keySize = sizeof(key);
        std::size_t valueSize = sizeof(value);
        std::size_t dataSize = keySize + valueSize;
        uint8_t* p = new uint8_t[dataSize];
        IF_TRUE_RETURN_VAL(p == nullptr, false);
        data_.emplace_back(DataBlock {
            .data = p,
            .len = dataSize
        });
        totalSize_ += dataSize;
        HDF_LOGD("key=%{public}d, keySize=%{public}zu, valueSize=%{public}zu, " \
                 "dataSize=%{public}zu, totalSize_=%{public}zu",
                 key, keySize, valueSize, dataSize, totalSize_);
        errno_t ret = memset_s(p, dataSize, 0, dataSize);
        IF_TRUE_RETURN_VAL(ret != EOK, false);
        ret = memcpy_s(p, dataSize, reinterpret_cast<uint8_t*>(&key), keySize);
        IF_TRUE_RETURN_VAL(ret != EOK, false);
        ret = memcpy_s(p + keySize, valueSize, reinterpret_cast<uint8_t*>(&value), valueSize);
        IF_TRUE_RETURN_VAL(ret != EOK, false);
        return true;
    }
    bool Finalize(std::vector<uint8_t>& dst);
    bool AddDataFromFile(OHOS::HDI::Codec::Image::V2_0::PropertyType key, const std::string& filePath);
    bool Finalize(OHOS::HDI::Codec::Image::V2_0::SharedBuffer& buffer);
private:
    struct DataBlock {
        uint8_t* data = nullptr;
        std::size_t len = 0;
    };
private:
    bool CopyDataTo(uint8_t* dstStart);
private:
    std::list<DataBlock> data_;
    std::size_t totalSize_ = 0;
};
} // OHOS::VDI::HEIF
#endif // OHOS_HDI_CODEC_IMAGE_V2_0_BUFFER_HELPER