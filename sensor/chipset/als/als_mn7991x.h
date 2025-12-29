/*
 * Copyright (c) 2023 Nanjing Xiaoxiongpai Intelligent Technology Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef ALS_MN7991X_H
#define ALS_MN7991X_H

#include "sensor_als_driver.h"
#include "sensor_config_parser.h"

#define DEVREG_IR_DATAL          0x28
#define DEVREG_IR_DATAH          0x29
#define DEVREG_ALS_DATAL         0x2A
#define DEVREG_ALS_DATAH         0x2B

#define MN7991X_READ_VALUE_DELAY         180

struct Mn7991xDrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* ALS_MN7991X_H */
