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

#include "usbqueryports_fuzzer.h"
#include "usb_port_impl.h"
#include "hdf_log.h"
#include "securec.h"
#include "usbcommonfunction_fuzzer.h"
#include "v1_0/iusb_interface.h"

using namespace OHOS::HDI::Usb::V1_0;

namespace OHOS {
namespace USB {
bool UsbQueryPortsFuzzTest(const uint8_t *data, size_t size)
{
    (void)size;
    (void)data;
    sptr<HDI::Usb::V2_0::IUsbPortInterface> usbPortInterface_ = nullptr;
    usbPortInterface_ = HDI::Usb::V2_0::IUsbPortInterface::Get();
    if (usbPortInterface_ == nullptr) {
        HDF_LOGE("%{public}s:usbPortInterface_::Get() failed.", __func__);
        return false;
    }
    std::vector<HDI::Usb::V2_0::UsbPort> portList;
    auto ret = usbPortInterface_->QueryPorts(portList);
    if (ret != 0) {
        return false;
    }
    
    return true;
}
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::USB::UsbQueryPortsFuzzTest(data, size);
    return 0;
}