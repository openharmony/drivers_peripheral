/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <hdf_log.h>
#include <image_auto_initer.h>
#include <securec.h>
#include <vector>
#include "ashmem.h"
#include "v2_1/icodec_image.h"
#include "v1_2/display_composer_type.h"
#include "v1_2/display_buffer_type.h"
#include "v1_2/include/idisplay_buffer.h"
#include "imagedoheifdecode_fuzzer.h"

using namespace OHOS::HDI::Codec::Image::V2_1;
using namespace OHOS::HDI::Display::Buffer::V1_2;
using namespace OHOS::HDI::Display::Composer::V1_2;
using namespace OHOS;
using namespace std;
namespace OHOS {
namespace Codec {
namespace Image {

static uint32_t Convert2Uint32(const uint8_t *ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    return (ptr[0] << 24) | (ptr[1] << 16) |  // 24:bit offset, 16: bit offset, 1:byte offset
           (ptr[2] << 8) | (ptr[3]);          // 8:bit offset, 2: byte offset, 3:byte offset
}

static sptr<Ashmem> GetAshmem(const char *name, int32_t size)
{
    auto ashmem = Ashmem::CreateAshmem(name, size);
    if (ashmem == nullptr) {
        HDF_LOGE("%{public}s: ashmem init failed\n", __func__);
        return ashmem;
    }
    if (!ashmem->MapReadAndWriteAshmem()) {
        HDF_LOGE("%{public}s: ashmem map failed\n", __func__);
        return ashmem;
    }
    return ashmem;
}

static void CloseAshmem(sptr<Ashmem> ashmem)
{
    if (ashmem != nullptr) {
        ashmem->UnmapAshmem();
        ashmem->CloseAshmem();
    }
}

static bool CreateAshmem(const CodecHeifDecInfo &decInfo, std::vector<sptr<Ashmem>> &inputs, uint8_t *data, size_t size)
{
    static constexpr uint32_t XPS_CNT = 1;
    uint32_t gridCnt = decInfo.gridInfo.enableGrid ? (decInfo.gridInfo.rows * decInfo.gridInfo.cols) : 1;
    uint32_t inputSize = XPS_CNT + gridCnt;
    for (uint32_t i = 0; i < inputSize; i++) {
        int32_t asmSize = 4;
        sptr<OHOS::Ashmem> asmptr = GetAshmem("fuzz_ashmem", asmSize);
        if (asmptr == nullptr) {
            return false;
        }
        int32_t len = (size > asmSize) ? asmSize : size;
        if (!asmptr->WriteToAshmem(data, len, 0)) {
            CloseAshmem(asmptr);
            HDF_LOGE("%{public}s: writing ashmem failed\n", __func__);
            return false;
        }

        inputs.push_back(asmptr);
    }
    return true;
}

static bool CreateNativeBuffer(sptr<NativeBuffer> &output, const CodecHeifDecInfo &decInfo)
{
    OHOS::HDI::Display::Buffer::V1_2::IDisplayBuffer *bufferMgr =
        OHOS::HDI::Display::Buffer::V1_2::IDisplayBuffer::Get();
    uint64_t usage = OHOS::HDI::Display::Composer::V1_2::HBM_USE_CPU_READ |
                     OHOS::HDI::Display::Composer::V1_2::HBM_USE_CPU_WRITE |
                     OHOS::HDI::Display::Composer::V1_2::HBM_USE_MEM_DMA;
    AllocInfo alloc = {.width = decInfo.gridInfo.displayWidth,
                       .height = decInfo.gridInfo.displayHeight,
                       .usage = usage,
                       .format = OHOS::HDI::Display::Composer::V1_2::PIXEL_FMT_YCBCR_420_SP};
    BufferHandle *handle = nullptr;
    int32_t ret = bufferMgr->AllocMem(alloc, handle);
    if (ret != HDF_SUCCESS) {
        return false;
    }
    output = new NativeBuffer();
    output->SetBufferHandle(handle, true);
    return true;
}

static uint32_t GetUInt32AndMove(uint8_t *data, uint8_t *&currentPos, size_t size)
{
    uint32_t value = Convert2Uint32(currentPos);
    if ((currentPos + sizeof(uint32_t) + sizeof(uint32_t)) > (data + size)) {
        currentPos = data;
    } else {
        currentPos += sizeof(uint32_t);
    }
    return value;
}

static bool FillHeifDecInfo(CodecHeifDecInfo &decInfo, uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return false;
    }
    constexpr uint32_t SIZE_FACTOR = 8192;
    constexpr uint32_t ROW_COL_FACTOR = 1024;
    constexpr uint32_t SAMPLE_FACTOR = 20;
    constexpr uint8_t EVEN_FACTOR = 2;
    uint8_t *currentPos = data;
    decInfo.gridInfo.displayWidth = GetUInt32AndMove(data, currentPos, size) % SIZE_FACTOR;
    decInfo.gridInfo.displayHeight = GetUInt32AndMove(data, currentPos, size) % SIZE_FACTOR;
    decInfo.gridInfo.enableGrid = *currentPos % EVEN_FACTOR;
    decInfo.gridInfo.tileWidth = GetUInt32AndMove(data, currentPos, size) % SIZE_FACTOR;
    decInfo.gridInfo.tileHeight = GetUInt32AndMove(data, currentPos, size) % SIZE_FACTOR;
    decInfo.gridInfo.cols = GetUInt32AndMove(data, currentPos, size) % ROW_COL_FACTOR;
    decInfo.gridInfo.rows = GetUInt32AndMove(data, currentPos, size) % ROW_COL_FACTOR;
    decInfo.sampleSize = GetUInt32AndMove(data, currentPos, size) % SAMPLE_FACTOR;

    return true;
}

bool DoHeifDecode(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(unsigned int)) {
        return false;
    }

    sptr<ICodecImage> image = ICodecImage::Get(false);
    if (image == nullptr) {
        HDF_LOGE("%{public}s: get ICodecImage failed\n", __func__);
        return false;
    }
    CodecImageRole role = CodecImageRole(*data);
    ImageAutoIniter autoIniter(image, role);

    uint8_t *rawData = const_cast<uint8_t *>(data);

    CodecHeifDecInfo decInfo;
    if (!FillHeifDecInfo(decInfo, rawData, size)) {
        return false;
    }

    std::vector<sptr<Ashmem>> inputs;
    CreateAshmem(decInfo, inputs, rawData, size);
    sptr<NativeBuffer> output = nullptr;
    CreateNativeBuffer(output, decInfo);

    auto err = image->DoHeifDecode(inputs, output, decInfo);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: DoHeifDecode return %{public}d", __func__, err);
    }
    for (auto &input : inputs) {
        CloseAshmem(input);
    }

    return true;
}
}  // namespace Image
}  // namespace Codec
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Codec::Image::DoHeifDecode(data, size);
    return 0;
}
