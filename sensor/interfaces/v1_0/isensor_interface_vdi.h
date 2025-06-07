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
#include "v3_0/isensor_interface.h"
#include "hdf_log.h"

struct SensorHandle : public OHOS::HDI::Sensor::V3_0::DeviceSensorInfo {
    bool operator == (const SensorHandle& other) const
    {
#ifdef TV_FLAG
        return deviceId == other.deviceId && sensorType == other.sensorType && sensorId == other.sensorId &&
                location == other.location;
#else
        return sensorType == other.sensorType;
#endif
    }

    bool operator < (const SensorHandle& other) const
    {
        if (sensorType != other.sensorType) {
            return sensorType < other.sensorType;
        }
        if (sensorId != other.sensorId) {
            return sensorId < other.sensorId;
        }
        if (deviceId != other.deviceId) {
            return deviceId < other.deviceId;
        }
        return location < other.location;
    }
};

namespace std {
    template <>
    struct hash<SensorHandle> {
        std::size_t operator()(const SensorHandle& obj) const
        {
#ifdef TV_FLAG
            std::size_t h1 = std::hash<int64_t>{}(obj.deviceId);
            std::size_t h2 = std::hash<int64_t>{}(obj.sensorType);
            std::size_t h3 = std::hash<int64_t>{}(obj.sensorId);
            std::size_t h4 = std::hash<int64_t>{}(obj.location);

            return h1 ^ h2 ^ h3 ^ h4;
#else
            std::size_t h2 = std::hash<int64_t>{}(obj.sensorType);

            return h2;
#endif
        }
    };
}

#define SENSOR_HANDLE_TO_STRING(sensorHandle) ("deviceId" + std::to_string((sensorHandle).deviceId) + "sensorType" + \
    std::to_string((sensorHandle).sensorType) + "sensorId" + std::to_string((sensorHandle).sensorId) + "location" + \
    std::to_string((sensorHandle).location))
#define SENSOR_HANDLE_TO_C_STR(sensorHandle) ("deviceId" + std::to_string((sensorHandle).deviceId) + "sensorType" + \
    std::to_string((sensorHandle).sensorType) + "sensorId" + std::to_string((sensorHandle).sensorId) + "location" + \
    std::to_string((sensorHandle).location)).c_str()

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
    struct SensorHandle sensorHandle;
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
    struct SensorHandle sensorHandle;
    int32_t ddrSize;
    int32_t minRateLevel;
    int32_t maxRateLevel;
    uint64_t memAddr;
    int32_t reserved;
};

class ISensorInterfaceVdi {
public:
//V1_1
    virtual ~ISensorInterfaceVdi() = default;
    virtual int32_t Init()
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetAllSensorInfo(std::vector<HdfSensorInformationVdi>& info)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t Enable(int32_t sensorId)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t Disable(int32_t sensorId)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t SetBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t SetMode(int32_t sensorId, int32_t mode)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t SetOption(int32_t sensorId, uint32_t option)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t Register(int32_t groupId, const sptr<ISensorCallbackVdi>& callbackObj)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t Unregister(int32_t groupId, const sptr<ISensorCallbackVdi>& callbackObj)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t SetSaBatch(int32_t sensorId, int64_t samplingInterval, int64_t reportInterval)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };

//V3_0
    virtual int32_t GetDeviceSensorInfo(int32_t deviceId, std::vector<HdfSensorInformationVdi>& info)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t GetSdcSensorInfo(std::vector<SdcSensorInfoVdi>& sdcSensorInfo)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t Enable(SensorHandle sensorHandle)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t Disable(SensorHandle sensorHandle)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t SetBatch(SensorHandle sensorHandle, int64_t samplingInterval, int64_t reportInterval)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t SetMode(SensorHandle sensorHandle, int32_t mode)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t SetOption(SensorHandle sensorHandle, uint32_t option)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t RegSensorPlugCallBack(const sptr<ISensorPlugCallback>& callbackObj)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t UnRegSensorPlugCallBack(const sptr<ISensorPlugCallback>& callbackObj)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
        return HDF_SUCCESS;
    };
    virtual int32_t SetSaBatch(SensorHandle sensorHandle, int64_t samplingInterval, int64_t reportInterval)
    {
        HDF_LOGI("%{public}s: only in Hdi return", __func__);
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
