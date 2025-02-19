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

#include <hdf_log.h>

#include "usb_sa_subscriber.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG UsbSaSubscriber

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {
constexpr int32_t LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED = 1;
UsbdLoadService UsbSaSubscriber::loadUsbService_ = {USB_SYSTEM_ABILITY_ID};
UsbdLoadService UsbSaSubscriber::loadHdfEdm_ = {HDF_EXTERNAL_DEVICE_MANAGER_SA_ID};
UsbSaSubscriber::UsbSaSubscriber() {}
int32_t UsbSaSubscriber::LoadUsbSa(const int32_t &eventId)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (eventId == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
        if (loadUsbService_.LoadService() != 0) {
            HDF_LOGE("loadUsbService_ LoadService error");
            return HDF_FAILURE;
        }
        if (loadHdfEdm_.LoadService() != 0) {
            HDF_LOGE("loadHdfEdm_ LoadService error");
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}
} // namespace V1_2
} // namespace USB
} // namespace HDI
} // namespace OHOS
