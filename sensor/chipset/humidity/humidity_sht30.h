/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef HUMIDITY_SHT30_H
#define HUMIDITY_SHT30_H

#include "sensor_config_parser.h"
#include "sensor_humidity_driver.h"

/* Humidity registers addr */
#define SHT30_HUM_DATA_ADDR             0x240B  // Data

/* Humidity data */
#define SHT30_HUM_DATA_BUF_LEN          6
#define SHT30_HUM_VALUE_INDEX_ZERO      0
#define SHT30_HUM_VALUE_INDEX_ONE       1
#define SHT30_HUM_VALUE_INDEX_TWO       2
#define SHT30_HUM_VALUE_INDEX_THREE     3
#define SHT30_HUM_VALUE_INDEX_FOUR      4
#define SHT30_HUM_VALUE_INDEX_FIVE      5

#define SHT30_HUM_SLOPE                 10000      // 100.0 * 100
#define SHT30_HUM_RESOLUTION            0xFFFF
#define SHT30_HUM_SHFIT_1_BIT           1

/* Humidity crc8 */
#define SHT30_HUM_CRC8_BASE             0xFF
#define SHT30_HUM_CRC8_MASK             0x80
#define SHT30_HUM_CRC8_POLYNOMIAL       0x31
#define SHT30_HUM_CRC8_LEN              2

int32_t DetectHumiditySht30Chip(struct SensorCfgData *data);

struct Sht30DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* HUMIDITY_SHT30_H */
