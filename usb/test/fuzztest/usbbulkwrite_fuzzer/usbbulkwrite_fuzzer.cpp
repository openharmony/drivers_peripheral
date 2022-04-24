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

#include "usbbulkwrite_fuzzer.h"
#include "usbd_client.h"
#include "hdf_log.h"
#include "usb_errors.h"
#include "UsbSubscriberTest.h"

#include <unistd.h>

namespace OHOS {
namespace USB {
    static const int32_t SLEEP_TIME = 3;
    static const int32_t DEFAULT_PORT_ID = 1;
    static const int32_t DEFAULT_ROLE_HOST = 1;
    static const int32_t DEFAULT_ROLE_DEVICE = 2;

    bool UsbBulkWriteFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        int32_t ret = UsbdClient::GetInstance().SetPortRole(DEFAULT_PORT_ID, DEFAULT_ROLE_HOST, DEFAULT_ROLE_HOST);
        sleep(SLEEP_TIME);
        if (ret != UEC_OK) {
            HDF_LOGE("%{public}s: set port role as host failed\n", __func__);
            return false;
        }

        sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
        ret = UsbdClient::GetInstance().BindUsbdSubscriber(subscriber);
        if (ret != UEC_OK) {
            HDF_LOGE("%{public}s: bind usbd subscriber failed\n", __func__);
            return false;
        }

        struct UsbDev dev = {subscriber->busNum_, subscriber->devAddr_};
        HDF_LOGI("%{public}s: busNum is %{public}d, devAddris %{public}d",
            __func__, subscriber->busNum_, subscriber->devAddr_);
        ret = UsbdClient::GetInstance().OpenDevice(dev);
        if (ret != UEC_OK) {
            HDF_LOGE("%{public}s: open device failed\n", __func__);
            return false;
        }

        sptr<Ashmem> ashmem;
        ret = UsbdClient::GetInstance().BulkWrite(dev, reinterpret_cast<const UsbPipe &>(data), ashmem);
        if (ret == UEC_OK) {
            HDF_LOGI("%{public}s: bulk Write succeed\n", __func__);
            result = true;
        }
        
        ret = UsbdClient::GetInstance().CloseDevice(dev);
        if (ret != UEC_OK) {
            HDF_LOGE("%{public}s: close device failed\n", __func__);
            return false;
        }

        ret = UsbdClient::GetInstance().SetPortRole(DEFAULT_PORT_ID, DEFAULT_ROLE_DEVICE, DEFAULT_ROLE_DEVICE);
        sleep(SLEEP_TIME);
        if (ret != UEC_OK) {
            HDF_LOGE("%{public}s: set port role as device failed\n", __func__);
            return false;
        }

        return result;
    }
} // namespace USB
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::USB::UsbBulkWriteFuzzTest(data, size);
    return 0;
}