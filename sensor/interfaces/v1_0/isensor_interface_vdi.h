/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_SENSOR_V1_1_ISENSORINTERFACE_VDI_H
#define OHOS_HDI_SENSOR_V1_1_ISENSORINTERFACE_VDI_H

#include "hdf_load_vdi.h"
#include "isensor_callback_vdi.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V1_1 {

#define HDI_SENSOR_VDI_LIBNAME "libhdi_sensor_impl.z.so"

struct HdfSensorInformationVdi {
    std::string sensorName;
    std::string vendorName;
    std::string firmwareVersion;
    std::string hardwareVersion;
    int32_t sensorTypeId;
    int32_t sensorId;
    float maxRange;
    float accuracy;
    float power;
    int64_t minDelay;
    int64_t maxDelay;
    uint32_t fifoMaxEventCount;
    uint32_t reserved;
};

struct SdcSensorInfoVdi {
    uint64_t offset;
    int32_t sensorId;
    int32_t ddrSize;
    int32_t minRateLevel;
    int32_t maxRateLevel;
    uint64_t memAddr;
    int32_t reserved;
};

class ISensorInterfaceVdi {
public:
    virtual ~ISensorInterfaceVdi() = default;
    virtual int32_t Init() = 0;
    virtual int32_t GetAllSensorInfo(std::vector<HdfSensorInformationVdi>& info) = 0;
    virtual int32_t Enable(int32_t sensorId) = 0;
    virtual int32_t Disable(int32_t sensorId) = 0;
    virtual int32_t SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval) = 0;
    virtual int32_t SetMode(int32_t sensorId, int32_t mode) = 0;
    virtual int32_t SetOption(int32_t sensorId, uint32_t option) = 0;
    virtual int32_t Register(int32_t groupId, const sptr<ISensorCallbackVdi>& callbackObj) = 0;
    virtual int32_t Unregister(int32_t groupId, const sptr<ISensorCallbackVdi>& callbackObj) = 0;
    virtual int32_t GetSdcSensorInfo(std::vector<SdcSensorInfoVdi>& sdcSensorInfo) { return HDF_SUCCESS; };
    virtual int32_t SetSaBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval)
    {
        return HDF_SUCCESS;
    };
};

struct WrapperSensorVdi {
    struct HdfVdiBase base;
    ISensorInterfaceVdi *sensorModule;
};
} // V1_1
} // Sensor
} // HDI
} // OHOS

#endif // OHOS_HDI_SENSOR_V1_1_ISENSORINTERFACE_VDI_H
