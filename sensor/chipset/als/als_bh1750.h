/*
 * Copyright (c) 2023 Nanjing Xiaoxiongpai Intelligent Technology Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef ALS_BH1750_H
#define ALS_BH1750_H

#include "sensor_als_driver.h"
#include "sensor_config_parser.h"

#define BH1750_TEMP_DATA_BUF_LEN          2
#define BH1750_TEMP_VALUE_IDX_ZERO        0
#define BH1750_TEMP_VALUE_IDX_ONE         1

#define BH1750_TEMP_CONSATNT_1          10000
#define BH1750_TEMP_CONSATNT_2          12

#define BH1750_CONTINUOUS_H_RES_MODE    0x10
#define BH1750_CONTINUOUS_H_RES_MODE2   0x11
#define BH1750_CONTINUOUS_L_RES_MODE    0x13
#define BH1750_ONE_TIME_H_RES_MODE      0x20
#define BH1750_ONE_TIME_H_RES_MODE2     0x21
#define BH1750_ONE_TIME_L_RES_MODE      0x23

#define BH1750_READ_VALUE_DELAY         180

struct BH1750AlsData {
    int32_t als;
};

struct Bh1750DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* ALS_BH1750_H */
