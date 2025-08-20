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

#include "usbdeviceauthorize_fuzzer.h"
#include <unistd.h>
#include "hdf_log.h"
#include "securec.h"
#include "UsbSubscriberV2Test.h"
#include "v2_0/iusb_host_interface.h"
#include "v2_0/iusb_device_interface.h"
#include "v2_0/usb_types.h"

using namespace OHOS;
using namespace OHOS::HDI::Usb::V2_0;

namespace OHOS {
namespace USB {
struct Parameters {
    uint8_t busNum;
    uint8_t devAddr;
    bool authorized;
}

bool UsbDeviceAuthorizeFuzzTest(const uint8_t *data, size_t size)
{
    (void)size;
    
    sptr<IUsbDeviceInterface> usbDeviceInterface_ = nullptr;
    usbDeviceInterface_ = HDI::Usb::V2_0::IUsbDeviceInterface::Get();
    if (usbDeviceInterface_ == nullptr) {
        HDF_LOGE("%{public}s:IUsbDeviceInterface_::Get() failed.", __func__);
        return false;
    }

    Parameters param;
    if (memcpy_s((void *)&param, sizeof(param), data, sizeof(param)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return false;
    }

    auto ret = usbDeviceInterface_->UsbDeviceAuthorize(param.busNum, param.devAddr, param.authorized);
    if (ret == HDF_SUCCESS) {
        HDF_LOGI("%{public}s: device authorize succeed", __func__);
    }
    return true;
}
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::USB::UsbDeviceAuthorizeFuzzTest(data, size);
    return 0;
}
