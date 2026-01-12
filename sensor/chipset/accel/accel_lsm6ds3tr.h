/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef ACCEL_LSM6DS3TR_H
#define ACCEL_LSM6DS3TR_H

#include "sensor_accel_driver.h"
#include "sensor_config_parser.h"

/* ACCEL DATA REGISTERS ADDR */
#define LSM6DS3TR_ACCEL_X_MSB_ADDR              0X29
#define LSM6DS3TR_ACCEL_X_LSB_ADDR              0X28
#define LSM6DS3TR_ACCEL_Y_MSB_ADDR              0X2B
#define LSM6DS3TR_ACCEL_Y_LSB_ADDR              0X2A
#define LSM6DS3TR_ACCEL_Z_MSB_ADDR              0X2D
#define LSM6DS3TR_ACCEL_Z_LSB_ADDR              0X2C

/* default HZ */

/* ACCEL RANGE */
#define LSM6DS3TR_ACC_SENSITIVITY_2G              61
#define LSM6DS3TR_ACC_SENSITIVITY_4G              122
#define LSM6DS3TR_ACC_SENSITIVITY_8G              244
#define LSM6DS3TR_ACC_SENSITIVITY_16G             488

struct LSM6DS3TRDrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* ACCEL_LSM6DS3TR_H */