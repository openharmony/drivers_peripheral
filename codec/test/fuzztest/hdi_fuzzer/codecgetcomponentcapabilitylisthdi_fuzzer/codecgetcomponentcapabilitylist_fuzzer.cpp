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

#include "codecgetcomponentcapabilitylist_fuzzer.h"
#include "codeccommon_fuzzer.h"

using namespace OHOS::HDI::Codec::V4_0;

namespace OHOS {
namespace Codec {
    bool CodecGetComponentCapabilityList(const uint8_t* data, size_t size)
    {
        if (data == nullptr) {
            return false;
        }

        OHOS::sptr<OHOS::HDI::Codec::V4_0::ICodecComponentManager> omxMgr_ = nullptr;

        omxMgr_ = ICodecComponentManager::Get(true);
        if (omxMgr_ == nullptr) {
            HDF_LOGE("%{public}s: ICodecComponentManager failed\n", __func__);
            return false;
        }

        int32_t count = 0;
        auto err = omxMgr_->GetComponentNum(count);
        if (err != HDF_SUCCESS || count <= 0) {
            HDF_LOGE("%{public}s GetComponentNum return %{public}d, count = %{public}d", __func__, err, count);
            return false;
        }

        std::vector<CodecCompCapability> caps;
        err = omxMgr_->GetComponentCapabilityList(caps,
            static_cast<uint32_t>(*(const_cast<uint8_t *>(data))));
        if (err != HDF_SUCCESS) {
            HDF_LOGE("%{public}s GetComponentCapabilityList return %{public}d", __func__, err);
            return false;
        }

        return true;
    }
} // namespace codec
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Codec::CodecGetComponentCapabilityList(data, size);
    return 0;
}
