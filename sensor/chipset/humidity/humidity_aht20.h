/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef HUMIDITY_AHT20_H
#define HUMIDITY_AHT20_H

#include "sensor_config_parser.h"
#include "sensor_humidity_driver.h"

/* Humidity registers addr */
#define AHT20_HUM_STATUS_ADDR              0x71 // Status
#define AHT20_HUM_RESET_ADDR               0xBA

#define AHT20_HUM_MEASURE_ADDR             0xAC // Measure
#define AHT20_HUM_MEASURE_ARG0             0x33
#define AHT20_HUM_MEASURE_ARG1             0x00

#define AHT20_HUM_CALIBRATION_ADDR         0xBE // Calibration
#define AHT20_HUM_CALIBRATION_ARG0         0x08
#define AHT20_HUM_CALIBRATION_ARG1         0x00

/* Humidity data */
#define AHT20_HUM_DATA_BUF_LEN          6
#define AHT20_HUM_VALUE_IDX_ZERO        0
#define AHT20_HUM_VALUE_IDX_ONE         1
#define AHT20_HUM_VALUE_IDX_TWO         2
#define AHT20_HUM_VALUE_IDX_THREE       3
#define AHT20_HUM_VALUE_IDX_FOUR        4
#define AHT20_HUM_VALUE_IDX_FIVE        5

#define AHT20_HUM_BUSY_SHIFT            7
#define AHT20_HUM_BUSY_MASK             (0x1 << AHT20_HUM_BUSY_SHIFT)
#define AHT20_HUM_IS_BUSY(status)       (((status) & AHT20_HUM_BUSY_MASK) >> AHT20_HUM_BUSY_SHIFT)

#define AHT20_HUM_CALI_SHIFT            3
#define AHT20_HUM_CALI_MASK             (0x1 << AHT20_HUM_CALI_SHIFT)
#define AHT20_HUM_IS_CALI(status)       (((status) & AHT20_HUM_CALI_MASK) >> AHT20_HUM_CALI_SHIFT)

#define AHT20_HUM_DELAY_MS              80
#define AHT20_HUM_STARTUP_MS            20
#define AHT20_HUM_CALIBRATION_MS        40

#define AHT20_HUM_SHFIT_FOUR_BITS       4
#define AHT20_HUM_SHFIT_EIGHT_BITS      8
#define AHT20_HUM_MASK                  0xF0

#define AHT20_HUM_SLOPE                 10000 // 100 * 100.0
#define AHT20_HUM_RESOLUTION            (0x1 << 20)
#define AHT20_HUM_RETRY_TIMES           5

struct Aht20DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* HUMIDITY_AHT20_H */
