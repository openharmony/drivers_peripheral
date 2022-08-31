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

#include "usbopendevice_fuzzer.h"
#include "hdf_log.h"
#include "securec.h"
#include "usbcommonfunction_fuzzer.h"
#include "v1_0/iusb_interface.h"

using namespace OHOS::HDI::Usb::V1_0;

namespace OHOS {
namespace USB {
bool UsbOpenDeviceFuzzTest(const uint8_t *data, size_t size)
{
    (void)size;
    sptr<IUsbInterface> usbInterface = IUsbInterface::Get();
    int32_t ret = usbInterface->SetPortRole(DEFAULT_PORT_ID, DEFAULT_ROLE_HOST, DEFAULT_ROLE_HOST);
    sleep(SLEEP_TIME);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: set port role as host failed", __func__);
        return false;
    }

    UsbDev dev;
    if (memcpy_s((void *)&dev, sizeof(dev), data, sizeof(dev)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return false;
    }

    ret = usbInterface->OpenDevice(dev);
    if (ret == HDF_SUCCESS) {
        HDF_LOGI("%{public}s: open device succeed", __func__);
        ret = usbInterface->CloseDevice(dev);
        if (ret == HDF_SUCCESS) {
            HDF_LOGI("%{public}s: close device succeed", __func__);
        }
    }

    return true;
}
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::USB::UsbOpenDeviceFuzzTest(data, size);
    return 0;
}