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

#ifndef OHOS_HDI_CODEC_IMAGE_V2_1_HEIF_ENCODE_TEST_HELPER
#define OHOS_HDI_CODEC_IMAGE_V2_1_HEIF_ENCODE_TEST_HELPER

#include <list>
#include <securec.h>
#include <sys/mman.h>
#include "hdf_log.h"
#include "ashmem.h"
#include "v2_1/icodec_image.h"

#define IF_TRUE_RETURN_VAL(cond, val)  \
    do {                               \
        if (cond) {                    \
            return val;                \
        }                              \
    } while (0)

class PropWriter {
public:
    PropWriter() = default;
    ~PropWriter()
    {
        for (auto iter = data_.begin(); iter != data_.end(); ++iter) {
            delete [] iter->data;
        }
        data_.clear();
    }
    template <typename T>
    bool AddData(OHOS::HDI::Codec::Image::V2_1::PropertyType key, T& value)
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
        errno_t ret = memset_s(p, dataSize, 0, dataSize);
        IF_TRUE_RETURN_VAL(ret != EOK, false);
        ret = memcpy_s(p, dataSize, reinterpret_cast<uint8_t*>(&key), keySize);
        IF_TRUE_RETURN_VAL(ret != EOK, false);
        ret = memcpy_s(p + keySize, valueSize, reinterpret_cast<uint8_t*>(&value), valueSize);
        IF_TRUE_RETURN_VAL(ret != EOK, false);
        return true;
    }
    bool Finalize(std::vector<uint8_t>& dst)
    {
        dst.clear();
        dst.resize(totalSize_);
        uint8_t* dstStart = reinterpret_cast<uint8_t*>(dst.data());
        size_t offset = 0;
        errno_t ret = EOK;
        for (auto iter = data_.begin(); (iter != data_.end()) && (ret == EOK); ++iter) {
            ret = memcpy_s(dstStart + offset, iter->len, iter->data, iter->len);
            offset += iter->len;
        }
        return (ret == EOK);
    }
private:
    struct DataBlock {
        uint8_t* data = nullptr;
        std::size_t len = 0;
    };
private:
    std::list<DataBlock> data_;
    std::size_t totalSize_ = 0;
};
#endif // OHOS_HDI_CODEC_IMAGE_V2_1_HEIF_ENCODE_TEST_HELPER