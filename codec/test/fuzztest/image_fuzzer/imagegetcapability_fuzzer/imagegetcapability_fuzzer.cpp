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

#include "imagegetcapability_fuzzer.h"
#include <hdf_log.h>
#include <vector>
#include "v1_0/icodec_image.h"
using namespace OHOS::HDI::Codec::Image::V1_0;
using namespace OHOS;
using namespace std;

extern "C" __attribute__((visibility("default"))) int dlclose(void* handle)
{
    return 0;
}

namespace OHOS {
namespace Codec {
namespace Image {
bool GetCapabilityList(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }

    sptr<ICodecImage> image = ICodecImage::Get(false);
    if (image == nullptr) {
        HDF_LOGE("%{public}s: get ICodecImage failed\n", __func__);
        return false;
    }

    vector<CodecImageCapability> caps;
    auto err = image->GetImageCapability(caps);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetImageCapability return %{public}d", __func__, err);
    }
    return true;
}
}  // namespace Image
}  // namespace Codec
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Codec::Image::GetCapabilityList(data, size);
    return 0;
}
