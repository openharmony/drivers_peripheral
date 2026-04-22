/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "serial_device_callback.h"
#include <hdf_base.h>
#include <hdf_log.h>

#undef LOG_TAG
#define LOG_TAG "SERIAL_IMPL"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002519

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {
#define HDF_LOG_TAG hdf_serial_device_callback

SerialDeviceCallback::SerialDeviceCallback(const sptr<ISerialDeviceCallback>& callback) : callback_(callback)
{
    HDF_LOGD("%{public}s called!", __func__);
}

int32_t SerialDeviceCallback::OnDeviceOffline()
{
    if (callback_ != nullptr) {
        return callback_->OnDeviceOffline();
    }
    return HDF_SUCCESS;
}

int32_t SerialDeviceCallback::OnReadData(const std::vector<int8_t>& data, uint32_t dataLen)
{
    HDF_LOGD("%{public}s called, dataLen=%{public}u!", __func__, dataLen);
    if (callback_ != nullptr) {
        return callback_->OnReadData(data, dataLen);
    }
    return HDF_SUCCESS;
}

} // V1_0
} // Serials
} // HDI
} // OHOS
