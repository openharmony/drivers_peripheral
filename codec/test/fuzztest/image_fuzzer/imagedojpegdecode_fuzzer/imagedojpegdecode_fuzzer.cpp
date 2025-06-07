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

#include "imagedojpegdecode_fuzzer.h"
#include <hdf_log.h>
#include <image_auto_initer.h>
#include <securec.h>
#include <vector>
#include "image_common.h"
#include "v2_1/icodec_image.h"
using namespace OHOS::HDI::Codec::Image::V2_1;
using namespace OHOS;
using namespace std;

extern "C" __attribute__((visibility("default"))) int dlclose(void* handle)
{
    return 0;
}

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

static bool FillCodecJpegDecInfo(CodecJpegDecInfo &decInfo, uint8_t *data, size_t size)
{
    uint8_t *dataEnd = data + size - 1;
    if (dataEnd < data + sizeof(decInfo.imageWidth)) {
        return false;
    }
    decInfo.imageWidth = Convert2Uint32(data);
    data += sizeof(decInfo.imageWidth);

    if (dataEnd < data + sizeof(decInfo.imageHeight)) {
        return false;
    }
    decInfo.imageHeight = Convert2Uint32(data);
    data += sizeof(decInfo.imageHeight);

    if (dataEnd < data + sizeof(decInfo.dataPrecision)) {
        return false;
    }
    decInfo.dataPrecision = Convert2Uint32(data);
    data += sizeof(decInfo.dataPrecision);

    if (dataEnd < data + sizeof(decInfo.numComponents)) {
        return false;
    }
    decInfo.numComponents = Convert2Uint32(data);
    data += sizeof(decInfo.numComponents);

    if (dataEnd < data + sizeof(decInfo.restartInterval)) {
        return false;
    }
    decInfo.restartInterval = Convert2Uint32(data);
    data += sizeof(decInfo.restartInterval);

    if (dataEnd < data + sizeof(decInfo.sampleSize)) {
        return false;
    }
    decInfo.sampleSize = Convert2Uint32(data);
    data += sizeof(decInfo.sampleSize);

    if (dataEnd < data + sizeof(decInfo.compressPos)) {
        return false;
    }
    decInfo.compressPos = Convert2Uint32(data);
    data += sizeof(decInfo.compressPos);

    if (dataEnd < data + sizeof(decInfo.arithCode)) {
        return false;
    }
    decInfo.compressPos = *data++;
    if (dataEnd < data + sizeof(decInfo.progressiveMode)) {
        return false;
    }
    decInfo.progressiveMode = *data++;
    return true;
}

bool DoJpegDecode(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    sptr<ICodecImage> image = ICodecImage::Get(false);
    if (image == nullptr) {
        HDF_LOGE("%{public}s: get ICodecImage failed\n", __func__);
        return false;
    }
    CodecImageRole role = CodecImageRole(*data);
    ImageAutoIniter autoIniter(image, role);

    CodecImageBuffer inBuffer;
    FillDataImageBuffer(inBuffer);
    CodecImageBuffer outBuffer;
    FillDataImageBuffer(outBuffer);
    uint8_t *rawData = const_cast<uint8_t *>(data);
    CodecJpegDecInfo decInfo;
    if (!FillCodecJpegDecInfo(decInfo, rawData, size)) {
        HDF_LOGE("%{public}s: FillCodecJpegDecInfo failed\n", __func__);
        return false;
    }

    auto err = image->DoJpegDecode(inBuffer, outBuffer, decInfo);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s DoJpegDecode return %{public}d", __func__, err);
    }
    return true;
}
}  // namespace Image
}  // namespace Codec
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Codec::Image::DoJpegDecode(data, size);
    return 0;
}
