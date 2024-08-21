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

#include "imagedoheifencode_fuzzer.h"
#include <hdf_log.h>
#include <image_auto_initer.h>
#include <securec.h>
#include <vector>
#include "image_common.h"
#include "encode_heif_helper.h"
#include "v2_0/icodec_image.h"
using namespace OHOS::HDI::Codec::Image::V2_0;
using namespace OHOS;
using namespace std;
namespace OHOS {
namespace Codec {
namespace Image {


bool DoHeifEncode(const uint8_t *data, size_t size)
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
    uint8_t decision = (*rawData) % 2;
    rawData += sizeof(decision);

    OHOS::VDI::HEIF::HeifEncodeHelper heifHelper;
    heifHelper.Reset();

    if (decision) {
        if (!heifHelper.AssembleParamForTmap(rawData, size)) {
            HDF_LOGE("%{public}s: AssembleParamForTmap failed\n", __func__);
            return false;
        }
    } else {
        if (!heifHelper.AssembleParamForPrimaryImg(rawData, size)) {
            HDF_LOGE("%{public}s: AssembleParamForPrimaryImg failed\n", __func__);
            return false;
        }
    }

    SharedBuffer output;
    if (!heifHelper.AllocOutputBuffer(output)) {
        HDF_LOGE("%{public}s: AllocOutputBuffer failed\n", __func__);
        return false;
    }
    uint32_t filledLen = 0;

    auto err = image->DoHeifEncode(heifHelper.inputImgs_, heifHelper.inputMetas_, heifHelper.refs_, output, filledLen);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: DOHeifEncode return %{public}d", __func__, err);
    }

    return true;
}
}  // namespace Image
}  // namespace Codec
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Codec::Image::DoHeifEncode(data, size);
    return 0;
}
