/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef GYRO_MIC6200_H
#define GYRO_MIC6200_H

#include "sensor_gyro_driver.h"

#define MIC6200_CHIP_ID_ADDR         0x00
#define MIC6200_CHIP_ID_VALUE        0xF9

#define MIC6200_GYRO_X_LSB_ADDR      0x08
#define MIC6200_GYRO_X_MSB_ADDR      0x09
#define MIC6200_GYRO_Y_LSB_ADDR      0x0A
#define MIC6200_GYRO_Y_MSB_ADDR      0x0B
#define MIC6200_GYRO_Z_LSB_ADDR      0x0C
#define MIC6200_GYRO_Z_MSB_ADDR      0x0D

#define MIC6200_GYRO_SENSITIVITY_2000DPS_NUM    2000
#define MIC6200_GYRO_SENSITIVITY_2000DPS_DEN    32768

struct Mic6200DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* GYRO_MIC6200_H */