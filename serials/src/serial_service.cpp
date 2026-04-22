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

#include "serial_service.h"
#include <hdf_base.h>
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {
#undef LOG_TAG
#define LOG_TAG "SERIAL_IMPL"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002519

#define HDF_LOG_TAG hdf_serial_service

SerialService::SerialService()
{
    HDF_LOGD("%{public}s called!", __func__);
}

int32_t SerialService::QueryDevices(std::vector<SerialDeviceInfo>& devices)
{
    HDF_LOGD("%{public}s called!", __func__);
    return SerialDeviceManager::GetInstance().QueryDevices(devices);
}

int32_t SerialService::OpenDevice(const std::string& portName, const SerialConfig& config,
    const sptr<ISerialDeviceCallback>& cb, sptr<ISerialDevice>& device)
{
    HDF_LOGD("%{public}s called, handle=%{public}s!", __func__, portName.c_str());
    return SerialDeviceManager::GetInstance().OpenDevice(portName, config, cb, device);
}

} // V1_0
} // Serials
} // HDI
} // OHOS
extern "C" OHOS::HDI::Serials::V1_0::ISerials *SerialsImplGetInstance(void)
{
    return new (std::nothrow) OHOS::HDI::Serials::V1_0::SerialService();
}