/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef TEMPERATURE_AHT20_H
#define TEMPERATURE_AHT20_H

#include "sensor_config_parser.h"
#include "sensor_temperature_driver.h"

/* Temperature registers addr */
#define AHT20_TEMP_STATUS_ADDR               0x71 // Status
#define AHT20_TEMP_RESET_ADDR                0xBA

#define AHT20_TEMP_MEASURE_ADDR              0xAC // Measure
#define AHT20_TEMP_MEASURE_ARG0              0x33
#define AHT20_TEMP_MEASURE_ARG1              0x00

#define AHT20_TEMP_CALIBRATION_ADDR          0xBE // Calibration
#define AHT20_TEMP_CALIBRATION_ARG0          0x08
#define AHT20_TEMP_CALIBRATION_ARG1          0x00

/* Temperature data */
#define AHT20_TEMP_DATA_BUF_LEN          6
#define AHT20_TEMP_VALUE_IDX_ZERO        0
#define AHT20_TEMP_VALUE_IDX_ONE         1
#define AHT20_TEMP_VALUE_IDX_TWO         2
#define AHT20_TEMP_VALUE_IDX_THREE       3
#define AHT20_TEMP_VALUE_IDX_FOUR        4
#define AHT20_TEMP_VALUE_IDX_FIVE        5

#define AHT20_TEMP_BUSY_SHIFT            7
#define AHT20_TEMP_BUSY_MASK            (0x1 << AHT20_TEMP_BUSY_SHIFT)
#define AHT20_TEMP_IS_BUSY(status)      (((status) & AHT20_TEMP_BUSY_MASK) >> AHT20_TEMP_BUSY_SHIFT)

#define AHT20_TEMP_CALI_SHIFT            3
#define AHT20_TEMP_CALI_MASK             (0x1 << AHT20_TEMP_CALI_SHIFT)
#define AHT20_TEMP_IS_CALI(status)       (((status) & AHT20_TEMP_CALI_MASK) >> AHT20_TEMP_CALI_SHIFT)

#define AHT20_TEMP_DELAY_MS              80
#define AHT20_TEMP_STARTUP_MS            20
#define AHT20_TEMP_CALIBRATION_MS        40

#define AHT20_TEMP_SHFIT_BITS            8
#define AHT20_TEMP_MASK                  0x0F

#define AHT20_TEMP_CONSATNT              500  // 50 * 10
#define AHT20_TEMP_SLOPE                 2000 // 200 * 10
#define AHT20_TEMP_RESOLUTION            (0x1 << 20)
#define AHT20_TEMP_RETRY_TIMES           5

struct Aht20DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* TEMPERATURE_AHT20_H */
