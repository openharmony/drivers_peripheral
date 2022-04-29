/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "usbsetportrole_fuzzer.h"
#include "usbd_client.h"
#include "hdf_log.h"
#include "usb_errors.h"

namespace OHOS {
namespace USB {
    bool UsbSetPortRoleFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        int32_t ret = UsbdClient::GetInstance().SetPortRole(reinterpret_cast<int32_t>(data),
            reinterpret_cast<int32_t>(data), reinterpret_cast<int32_t>(data));
        if (ret == UEC_OK) {
            HDF_LOGI("%{public}s: set interface succeed\n", __func__);
            result = true;
        }
        return result;
    }
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::USB::UsbSetPortRoleFuzzTest(data, size);
    return 0;
}