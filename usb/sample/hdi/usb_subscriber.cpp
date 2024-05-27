/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <iostream>
#include <vector>
#include "hdf_log.h"
#include "osal_time.h"
#include "UsbSubscriberTest.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"

using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;

namespace {sptr<IUsbInterface> g_usbInterface = nullptr;}
constexpr int32_t BIND_TIME = 60;
int32_t main(int32_t argc, const char *argv[])
{
    g_usbInterface = IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed", __func__);
        return HDF_FAILURE;
    }
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    HDF_LOGI("%{public}s: bind usbd subscriber", __func__);
    if (g_usbInterface->BindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber failed", __func__);
        return HDF_FAILURE;
    }
    OsalSleep(BIND_TIME);
    HDF_LOGI("%{public}s: unbind usbd subscriber", __func__);
    if (g_usbInterface->UnbindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: unbind usbd subscriber failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
