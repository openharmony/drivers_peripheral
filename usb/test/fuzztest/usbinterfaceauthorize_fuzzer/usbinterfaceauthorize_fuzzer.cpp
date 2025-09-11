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

#include "usbinterfaceauthorize_fuzzer.h"
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
    uint8_t configId;
    uint8_t interfaceId;
    bool authorized;
};

bool UsbInterfaceAuthorizeFuzzTest(const uint8_t *data, size_t size)
{
    (void)size;
    
    sptr<IUsbHostInterface> usbHostInterface_ = nullptr;
    usbHostInterface_ = HDI::Usb::V2_0::IUsbHostInterface::Get();
    if (usbHostInterface_ == nullptr) {
        HDF_LOGE("%{public}s:IUsbHostInterface_::Get() failed.", __func__);
        return false;
    }
    sptr<IUsbDeviceInterface> usbDeviceInterface_ = nullptr;
    usbDeviceInterface_ = HDI::Usb::V2_0::IUsbDeviceInterface::Get();
    if (usbDeviceInterface_ == nullptr) {
        HDF_LOGE("%{public}s:IUsbDeviceInterface_::Get() failed.", __func__);
        return false;
    }
    sptr<OHOS::USB::UsbSubscriberTest> subscriber_ = nullptr;
    subscriber_ = new OHOS::USB::UsbSubscriberTest();
    if (usbHostInterface_->BindUsbdHostSubscriber(subscriber_) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd host subscriber_ failed", __func__);
        return false;
    }
    UsbDev dev = {subscriber_->busNum_, subscriber_->devAddr_};

    Parameters param;
    if (memcpy_s((void *)&param, sizeof(param), data, sizeof(param)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return false;
    }
    auto ret = usbDeviceInterface_->UsbInterfaceAuthorize(
        dev, param.configId, param.interfaceId, param.authorized);
    if (ret == HDF_SUCCESS) {
        HDF_LOGI("%{public}s: interface authorize succeed", __func__);
    }

    ret = usbHostInterface_->UnbindUsbdHostSubscriber(subscriber_);
    if (ret != 0) {
        HDF_LOGE("%{public}s: unbind usbd host subscriber_ failed", __func__);
        return false;
    }
    return true;
}
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::USB::UsbInterfaceAuthorizeFuzzTest(data, size);
    return 0;
}
