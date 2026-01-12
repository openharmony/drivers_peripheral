/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef PROXIMITY_STK33562_H
#define PROXIMITY_STK33562_H

#include "sensor_config_parser.h"
#include "sensor_proximity_driver.h"
#include <asm-generic/errno.h>

#define STK33562_PROX_MSB_ADDR 0X11    /* Proximity Data MSB */
#define STK33562_PROX_LSB_ADDR 0X12    /* Proximity Data LSB */


enum Stk33562RegAddr {
    STK33562_PROX_ADDR_MSB = 0,
    STK33562_PROX_ADDR_LSB = 1,
    STK33562_PROX_ADDR_NUM,
};

#define STK33562_PROX_THRESH_FAR 32     /* threshold */
#define STK33562_PROX_THRESH_NEAR 259    /* threshold */

int32_t DetectProximityStk33562Chip(struct SensorCfgData *data);

struct Stk33562DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* PROXIMITY_STK33562_H */
