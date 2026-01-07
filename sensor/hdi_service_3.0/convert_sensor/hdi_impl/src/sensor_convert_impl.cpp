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

#include "sensor_convert_impl.h"
#include <hdf_base.h>
#include <hdf_log.h>

#define HDF_LOG_TAG    sensor_extra_convert
#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN    0xD002516

namespace OHOS {
namespace HDI {
namespace SensorExtra {
namespace Convert {
namespace V1_0 {
extern "C" ISensorConvertInterfaces *SensorConvertInterfacesImplGetInstance(void)
{
    using OHOS::HDI::SensorExtra::Convert::V1_0::SensorConvertImpl;
    SensorConvertImpl *service = new (std::nothrow) SensorConvertImpl();
    if (service == nullptr) {
        return nullptr;
    }
    if (service->Init() != HDF_SUCCESS) {
        delete service;
        return nullptr;
    }
    return service;
}

int32_t SensorConvertImpl::Init()
{
    HDF_LOGI("%{public}s: SensorConvertImpl init success\n", __func__);
    return HDF_SUCCESS;
}

SensorConvertImpl::SensorConvertImpl()
{
}

int32_t SensorConvertImpl::ConvertSensorData(const HdfDeviceStatusPolicy& status,
    const HdfSensorData& inSensorData, HdfSensorData& outSensorData)
{
    (void)status;
    (void)inSensorData;
    (void)outSensorData;
    return HDF_ERR_NOT_SUPPORT;
}
} // namespace v1_0
} // namespace Convert
} // namespace SensorExtra
} // namespace HDI
} // namespace OHOS
