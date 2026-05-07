/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "usbgetcontroltransferdata_fuzzer.h"
#include <unistd.h>
#include "hdf_log.h"
#include "securec.h"
#include "v2_1/iusb_device_interface.h"

using namespace OHOS;
using namespace OHOS::HDI::Usb::V2_1;

namespace OHOS {
namespace USB {
    struct Parameters {
        int32_t eventId;
    };

    bool UsbGetControlTransferDataFuzzTest(const uint8_t *data, size_t size)
    {
        (void)size;

        sptr<OHOS::HDI::Usb::V2_1::IUsbDeviceInterface> usbDeviceInterface = nullptr;
        usbDeviceInterface = HDI::Usb::V2_1::IUsbDeviceInterface::Get();
        if (usbDeviceInterface == nullptr) {
            HDF_LOGE("%{public}s:IUsbDeviceInterface::Get() failed.", __func__);
            return false;
        }

        Parameters param;
        if (memcpy_s((void *)&param, sizeof(param), data, sizeof(param)) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s failed", __func__);
            return false;
        }

        std::vector<uint8_t> resultData;
        auto ret = usbDeviceInterface->GetControlTransferData(param.eventId, resultData);
        if (ret == HDF_SUCCESS) {
            HDF_LOGI("%{public}s: get control transfer data succeed, size=%{public}zu", __func__, resultData.size());
        }
        return true;
    }
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::USB::UsbGetControlTransferDataFuzzTest(data, size);
    return 0;
}
