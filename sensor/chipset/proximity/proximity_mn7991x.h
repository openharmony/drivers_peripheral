/*
 * Copyright (c) 2021-2022 xu
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef PROXIMITY_MN7991X_H
#define PROXIMITY_MN7991X_H

#include "sensor_config_parser.h"
#include "sensor_proximity_driver.h"


#define MN7991X_PROX_RAW_DATA_REG_L              0x55
#define MN7991X_PROXIMITY_THRESHOLD               100    // threshold

int32_t DetectProximityMn7991xChip(struct SensorCfgData *data);

struct Mn7991xDrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* PROXIMITY_MN7991X_H */