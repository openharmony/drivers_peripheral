/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef TEMPERATURE_SHT30_H
#define TEMPERATURE_SHT30_H

#include "sensor_config_parser.h"
#include "sensor_temperature_driver.h"

/* Temperature registers addr */
#define SHT30_TEMP_DATA_ADDR             0x240B // Temperature Data

/* Temperature data */
#define SHT30_TEMP_DATA_BUF_LEN          6
#define SHT30_TEMP_VALUE_IDX_ZERO        0
#define SHT30_TEMP_VALUE_IDX_ONE         1
#define SHT30_TEMP_VALUE_IDX_TWO         2
#define SHT30_TEMP_VALUE_IDX_THREE       3
#define SHT30_TEMP_VALUE_IDX_FOUR        4
#define SHT30_TEMP_VALUE_IDX_FIVE        5

#define SHT30_TEMP_CONSATNT              (-450)   // -45.0 * 10
#define SHT30_TEMP_SLOPE                 1750   // 175.0 * 10
#define SHT30_TEMP_SHFIT_1_BIT           1

/* Temperature crc8 */
#define SHT30_TEMP_CRC8_BASE             0xFF
#define SHT30_TEMP_CRC8_MASK             0x80
#define SHT30_TEMP_CRC8_POLYNOMIAL       0x31
#define SHT30_TEMP_CRC8_LEN              2

struct Sht30DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* TEMPERATURE_SHT30_H */
