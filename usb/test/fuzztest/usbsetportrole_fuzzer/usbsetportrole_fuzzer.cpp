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
#include "hdf_log.h"
#include "securec.h"
#include "v1_0/iusb_interface.h"

using namespace OHOS::HDI::Usb::V1_0;

namespace OHOS {
namespace USB {
    struct Parameters {
    int32_t portId;
    int32_t powerRole;
    int32_t dataRole;
};

bool UsbSetPortRoleFuzzTest(const uint8_t *data, size_t size)
{
    (void)size;
    Parameters param;
    if (memcpy_s((void *)&param, sizeof(param), data, sizeof(param)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return false;
    }
    sptr<IUsbInterface> usbInterface = IUsbInterface::Get();
    int32_t ret = usbInterface->SetPortRole(param.portId, param.powerRole, param.dataRole);
    if (ret == HDF_SUCCESS) {
        HDF_LOGI("%{public}s: set interface succeed", __func__);
    }
    return true;
}
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::USB::UsbSetPortRoleFuzzTest(data, size);
    return 0;
}