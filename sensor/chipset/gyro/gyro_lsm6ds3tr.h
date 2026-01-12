/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef GYRO_LSM6DS3TR_H
#define GYRO_LSM6DS3TR_H

#include "sensor_gyro_driver.h"
#include "sensor_config_parser.h"

/* GYRO DATA REGISTERS ADDR */
#define LSM6DS3TR_GYRO_X_LSB_ADDR 0X22
#define LSM6DS3TR_GYRO_X_MSB_ADDR 0X23
#define LSM6DS3TR_GYRO_Y_LSB_ADDR 0X24
#define LSM6DS3TR_GYRO_Y_MSB_ADDR 0X25
#define LSM6DS3TR_GYRO_Z_LSB_ADDR 0X26
#define LSM6DS3TR_GYRO_Z_MSB_ADDR 0X27

/* GYRO STATUS REGISTER ADDR */
#define LSM6DS3TR_STATUS_ADDR 0X1E

/* GYRO DATA READY */
#define LSM6DS3TR_GYRO_DATA_READY_MASK 0x02

/* GYRO ODR */
#define LSM6DS3TR_GYRO_ODR_RESERVED 0x00
#define LSM6DS3TR_GYRO_ODR_12HZ 0x10
#define LSM6DS3TR_GYRO_ODR_26HZ 0x20
#define LSM6DS3TR_GYRO_ODR_52HZ 0x30
#define LSM6DS3TR_GYRO_ODR_104HZ 0x40
#define LSM6DS3TR_GYRO_ODR_208HZ 0x50
#define LSM6DS3TR_GYRO_ODR_416HZ 0x60
#define LSM6DS3TR_GYRO_ODR_833HZ 0x70
#define LSM6DS3TR_GYRO_ODR_1666HZ 0x80
#define LSM6DS3TR_GYRO_ODR_3332HZ 0x90
#define LSM6DS3TR_GYRO_ODR_6664HZ 0xA0

/* GYRO RANGE */
#define LSM6DS3TR_GYRO_RANGE_125DPS (4375 / 1000)   /* 4.375mdps/s */
#define LSM6DS3TR_GYRO_RANGE_245DPS (8750 / 1000)   /* 8.75mdps/s */
#define LSM6DS3TR_GYRO_RANGE_500DPS (17500 / 1000)  /* 17.50mdps/s */
#define LSM6DS3TR_GYRO_RANGE_1000DPS 35             /* 35.00mdps/s */
#define LSM6DS3TR_GYRO_RANGE_2000PS 70              /* 70.00mdps/s */

struct Gyro_Lsm6ds3trDrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* GYRO_LSM6DS3TR_H */
