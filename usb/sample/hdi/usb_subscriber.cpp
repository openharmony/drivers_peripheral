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

#include "UsbSubscriberTest.h"

#include <iostream>
#include <vector>
#include "osal_time.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"

using namespace OHOS;
using namespace OHOS::USB;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;

sptr<IUsbInterface> g_usbInterface = nullptr;
#define BIND_TIME 60
int32_t main(int32_t argc, const char *argv[])
{
    g_usbInterface = IUsbInterface::Get();
    if (g_usbInterface == nullptr) {
        printf("%s:IUsbInterface::Get() failed\n", __func__);
        return HDF_FAILURE;
    }
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    printf("%s: bind usbd subscriber\n", __func__);
    if (g_usbInterface->BindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        printf("%s: bind usbd subscriber failed\n", __func__);
        return HDF_FAILURE;
    }
    OsalSleep(BIND_TIME);
    printf("%s: unbind usbd subscriber\n", __func__);
    if (g_usbInterface->UnbindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        printf("%s: unbind usbd subscriber failed\n", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
