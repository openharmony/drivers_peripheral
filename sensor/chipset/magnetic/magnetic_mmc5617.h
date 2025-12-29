/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */
 
#ifndef MAGNETIC_MMC5617_H
#define MAGNETIC_MMC5617_H

#include "sensor_config_parser.h"
#include "sensor_magnetic_driver.h"

#define MMC5617_MAGNETIC_GIN                     1000

/* MAGNETIC DATA REGISTERS ADDR */
#define MMC5617_MAGNETIC_X_MSB_ADDR              0X00
#define MMC5617_MAGNETIC_X_LSB_ADDR              0X01
#define MMC5617_MAGNETIC_Y_MSB_ADDR              0X02
#define MMC5617_MAGNETIC_Y_LSB_ADDR              0X03
#define MMC5617_MAGNETIC_Z_MSB_ADDR              0X04
#define MMC5617_MAGNETIC_Z_LSB_ADDR              0X05
#define MMC5617_STATUS_ADDR                      0X18

/*MAGNETIC DATA 16BIT OFFSET*/
#define	MMC5617_16BIT_OFFSET		32768

#define MMC5617_SENSITIVITY    1024


int32_t DetectMagneticMmc5617Chip(struct SensorCfgData *data);
int32_t ReadMmc5617Data(struct SensorCfgData *data);

struct Mmc5617DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* MAGNETIC_MMC5617_H */
