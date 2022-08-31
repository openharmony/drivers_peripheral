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

#include "usbcommonfunction_fuzzer.h"
#include "UsbSubscriberTest.h"
#include "hdf_log.h"

using namespace OHOS::HDI::Usb::V1_0;

namespace OHOS {
namespace USB {
int32_t UsbFuzzTestHostModeInit(UsbDev &dev, const sptr<IUsbInterface> &usbInterface)
{
    int32_t ret = usbInterface->SetPortRole(DEFAULT_PORT_ID, DEFAULT_ROLE_HOST, DEFAULT_ROLE_HOST);
    sleep(SLEEP_TIME);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: set port role as host failed", __func__);
        return ret;
    }

    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ret = usbInterface->BindUsbdSubscriber(subscriber);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber failed", __func__);
        return ret;
    }

    dev.busNum = subscriber->busNum_;
    dev.devAddr = subscriber->devAddr_;
    HDF_LOGI("%{public}s: busNum:%{public}d, devAddr:%{public}d", __func__, subscriber->busNum_, subscriber->devAddr_);
    ret = usbInterface->OpenDevice(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: open device failed", __func__);
        return ret;
    }
    return ret;
}
} // namespace USB
} // namespace OHOS