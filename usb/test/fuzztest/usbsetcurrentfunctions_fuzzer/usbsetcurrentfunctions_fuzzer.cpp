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

#include "usbsetcurrentfunctions_fuzzer.h"
#include "hdf_log.h"
#include "usbcommonfunction_fuzzer.h"
#include "v1_0/iusb_interface.h"

using namespace OHOS::HDI::Usb::V1_0;

namespace OHOS {
namespace USB {
bool UsbSetCurrentFunctionsFuzzTest(const uint8_t *data, size_t size)
{
    (void)size;
    sptr<IUsbInterface> usbInterface = IUsbInterface::Get();
    int32_t ret = usbInterface->SetPortRole(DEFAULT_PORT_ID, DEFAULT_ROLE_DEVICE, DEFAULT_ROLE_DEVICE);
    sleep(SLEEP_TIME);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: set port role as host failed", __func__);
        return ret;
    }

    int32_t timeout = *(reinterpret_cast<int32_t *>(*data));
    ret = usbInterface->SetCurrentFunctions(func);
    if (ret == HDF_SUCCESS) {
        HDF_LOGI("%{public}s: set interface succeed", __func__);
    }
    return true;
}
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::USB::UsbSetCurrentFunctionsFuzzTest(data, size);
    return 0;
}