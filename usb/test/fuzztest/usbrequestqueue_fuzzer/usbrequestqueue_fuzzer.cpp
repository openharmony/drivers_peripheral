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

#include "usbrequestqueue_fuzzer.h"
#include "UsbSubscriberTest.h"
#include "hdf_log.h"
#include "securec.h"
#include "usbcommonfunction_fuzzer.h"
#include "v1_0/iusb_interface.h"

using namespace OHOS::HDI::Usb::V1_0;

namespace OHOS {
constexpr size_t THRESHOLD = 10;
constexpr int32_t OFFSET = 4;
constexpr int32_t OFFSET_BYTE = 8;
namespace USB {
bool UsbRequestQueueFuzzTest(const uint8_t *data, size_t size)
{
    (void)size;
    UsbDev dev;
    sptr<IUsbInterface> usbInterface = IUsbInterface::Get();
    int32_t ret = UsbFuzzTestHostModeInit(dev, usbInterface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbFuzzTestHostModeInit failed", __func__);
        return false;
    }

    UsbPipe pipe;
    if (memcpy_s((void *)&pipe, sizeof(pipe), data, sizeof(pipe)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return false;
    }

    ret = usbInterface->RequestQueue(
        dev, pipe, reinterpret_cast<const std::vector<uint8_t> &>(std::move(data + OFFSET)),
        reinterpret_cast<const std::vector<uint8_t> &>(std::move(data + OFFSET_BYTE)));
    if (ret == HDF_SUCCESS) {
        HDF_LOGI("%{public}s: reg bulk callback succeed", __func__);
    }

    ret = usbInterface->CloseDevice(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: close device failed", __func__);
        return false;
    }
    return true;
}
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }
    OHOS::USB::UsbRequestQueueFuzzTest(data, size);
    return 0;
}