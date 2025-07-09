/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SENSOR_HDI_DUMP_H
#define SENSOR_HDI_DUMP_H
#include <vector>
#include "hdf_sbuf.h"
#include "devhost_dump_reg.h"
#include "sensor_type.h"
#include "sensor_if_service.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V3_0 {
enum {
    MEM_X = 1,
    MEM_XY = 3,
    MEM_XYZ = 4,
    MEM_UNCALIBRATED = 6,
    MEM_POSTURE = 8,
    MEM_SPE_RGB = 14,
    MEM_MAX_DATA_SIZE = MEM_SPE_RGB
};

class SensorHdiDump {
public:
    SensorHdiDump();
    ~SensorHdiDump();
    static int32_t DevHostSensorHdiDump(struct HdfSBuf *data, struct HdfSBuf *reply);

private:
    static int32_t SensorShowList(struct HdfSBuf *reply);
    static std::string SensorInfoDataToString(const float *data,
                                       const int64_t timesTamp,
                                       const int32_t dataDimension,
                                       const SensorHandle sensorHandle);
    static int32_t ShowData(const float *data,
                     const int64_t timesTamp,
                     const int32_t dataDimension,
                     const SensorHandle sensorHandle,
                     struct HdfSBuf *reply);
    static int32_t SensorShowData(struct HdfSBuf *reply);
    static int32_t SensorShowClient(struct HdfSBuf *reply);
};

int32_t GetSensorDump(struct HdfSBuf *data, struct HdfSBuf *reply);

} // V3_0
} // Sensor
} // HDI
} // OHOS

#endif //SENSOR_HDI_DUMP_H