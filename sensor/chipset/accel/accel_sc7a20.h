/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef ACCEL_SC7A20_H
#define ACCEL_SC7A20_H

#include "sensor_accel_driver.h"
#include "sensor_config_parser.h"

/* ACCEL DATA REGISTERS ADDR */
#define SC7A20_ACCEL_X_MSB_ADDR              0X29
#define SC7A20_ACCEL_X_LSB_ADDR              0X28
#define SC7A20_ACCEL_Y_MSB_ADDR              0X2b
#define SC7A20_ACCEL_Y_LSB_ADDR              0X2a
#define SC7A20_ACCEL_Z_MSB_ADDR              0X2d
#define SC7A20_ACCEL_Z_LSB_ADDR              0X2c
#define SC7A20_STATUS_ADDR                   0X27

/* default HZ */
#define SC7A20_ACCEL_DEFAULT_ODR_100HZ       100
#define SC7A20_ACCEL_DEFAULT_ODR_25HZ        25

/* ACCEL RANGE */
#define SC7A20_ACCEL_RANGE_2G                0X03
#define SC7A20_ACCEL_RANGE_4G                0X05
#define SC7A20_ACCEL_RANGE_8G                0X08
#define SC7A20_ACCEL_RANGE_16G               0X0C

/* ACC sensitivity */
#define SC7A20_ACC_SENSITIVITY_2G            61
#define SC7A20_ACC_SENSITIVITY_4G            122
#define SC7A20_ACC_SENSITIVITY_8G            244
#define SC7A20_ACC_SENSITIVITY_16G           488

/* ACCEL DATA READY */
#define SC7A20_ACCEL_DATA_READY_MASK         0x80

struct Sc7a20DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* ACCEL_SC7A20_H */
