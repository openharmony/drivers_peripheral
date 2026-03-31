/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "usbgetnonroothubs_fuzzer.h"
#include "hdf_log.h"
#include "v1_2/iusb_ddk.h"

using namespace OHOS::HDI::Usb::Ddk;

namespace OHOS {
namespace USB {
bool UsbGetNonRootHubsFuzzTest(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    
    sptr<V1_2::IUsbDdk> usbDdk = V1_2::IUsbDdk::Get();
    if (usbDdk == nullptr) {
        HDF_LOGE("%{public}s: get usb interface failed", __func__);
        return false;
    }

    std::vector<uint64_t> nonRootHubIds;
    int32_t ret = usbDdk->GetNonRootHubs(nonRootHubIds);
    if (ret == HDF_SUCCESS) {
        HDF_LOGI("%{public}s: GetNonRootHubs succeed, count: %{public}zu", __func__, nonRootHubIds.size());
    } else {
        HDF_LOGW("%{public}s: GetNonRootHubs failed: %{public}d", __func__, ret);
    }

    return true;
}
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::USB::UsbGetNonRootHubsFuzzTest(data, size);
    return 0;
}
