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

#include "UsbSubTest.h"
#include "hdf_log.h"
#include "usbd_type.h"
#include "usbd_wrapper.h"

namespace OHOS {
namespace USB {
int32_t UsbSubTest::DeviceEvent(const USBDeviceInfo &info)
{
    if (info.status == ACT_UPDEVICE || info.status == ACT_DOWNDEVICE) {
        return 0;
    }
    busNum_ = info.busNum;
    devAddr_ = info.devNum;
    HDF_LOGI("%{public}s: busNum is %{public}d, devAddr is %{public}d", __func__, busNum_, devAddr_);
    return 0;
}
} // namespace USB
} // namespace OHOS
