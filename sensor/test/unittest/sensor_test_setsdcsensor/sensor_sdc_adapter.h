/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ai hold posture adpter process.
 */
#ifndef SIGNALAI_ADAPTER_H
#define SIGNALAI_ADAPTER_H

#include "v3_0/isensor_interface.h"
#include "v3_0/sensor_types.h"

namespace OHOS {
namespace Telephony {

class SignalAIAdapter {
public:
    ~SignalAIAdapter();
    bool OpenSignalHubDevice();
    void CloseSignalHubDevice();
    bool InitSensors();
    void ReleaseSensors();
    int GetAccAddrOffset();
    int GetGyrAddrOffset();
    uint8_t* GetSensorShareAddr();
    bool SignalHubDeviceMmap();
    bool SetSdcSensors();
    bool GetSdcFifoWriteIdx(unsigned int& accFifoWriteIdx, unsigned int& gyrFifoWriteIdx, unsigned int& accFifoCount,
        unsigned int& gyrFifoCount);
    void SignalHubDeviceMunmap();
private:
    int32_t signalHubDeviceFd_ = -1;
    uint8_t* sensorShareAddr_ = nullptr;
    int accAddrOffset_ = -1;
    int gyrAddrOffset_ = -1;
    bool accSensorOn_ = false;
    bool gyrSensorOn_ = false;
    sptr<HDI::Sensor::V3_0::ISensorInterface> sensorInterface_ = nullptr;
    uint32_t accMaxFifoCount_ = 0;
    uint32_t gyrMaxFifoCount_ = 0;
    HDI::Sensor::V3_0::DeviceSensorInfo accSensorInfo_ = {-1, HDI::Sensor::V3_0::HDF_SENSOR_TYPE_ACCELEROMETER, 0, 1};
    HDI::Sensor::V3_0::DeviceSensorInfo gyrSensorInfo_ = {-1, HDI::Sensor::V3_0::HDF_SENSOR_TYPE_GYROSCOPE, 0, 1};
};

}  // Telephony
}  // OHOS
#endif  // SIGNALAI_ADAPTER_H