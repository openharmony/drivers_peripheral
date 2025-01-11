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

#include "usbgetdevices_fuzzer.h"
#include "hdf_log.h"
#include "securec.h"
#include "v1_1/iusb_ddk.h"

using namespace OHOS::HDI::Usb::Ddk;

namespace OHOS {
namespace USB {
bool UsbGetDevicesTest(const uint8_t *data, size_t size)
{
    sptr<V1_1::IUsbDdk> usbDdk = V1_1::IUsbDdk::Get();
    if (usbDdk == nullptr) {
        return false;
    }

    size_t numElements = size / sizeof(uint64_t);
    std::vector<uint64_t> devices;
    devices.reserve(numElements);

    for (size_t i = 0; i < numElements; ++i) {
        uint64_t value;
        std::copy(data + i * sizeof(uint64_t),
                  data + (i + 1) * sizeof(uint64_t),
                  reinterpret_cast<uint8_t*>(&value));
        devices.push_back(value);
    }

    int ret = usbDdk->GetDevices(devices);
    if (ret != HDF_SUCCESS) {
        return false;
    }
    HDF_LOGI("%{public}s: get devices succeed", __func__);
    return true;
}
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::USB::UsbGetDevicesTest(data, size);
    return 0;
}