/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef ACCEL_MIC6200_H
#define ACCEL_MIC6200_H

#include "sensor_device_manager.h"
#include "hdf_device_desc.h"

#define MIC6200_CHIP_NAME            "mic6200"
/* sensitivity for 8g range, converted to fixed-point with MICRO_UNIT multiplier */
#define MIC6200_ACC_SENSITIVITY_8G_NUM   2394  /* numerator part of 0.002394 */
#define MIC6200_ACC_SENSITIVITY_8G_DEN    1000000 /* denominator part of 0.002394 */

/* MIC6200 Register Map */
#define MIC6200_CHIP_ID_ADDR         0x00    /* Chip ID register */
#define MIC6200_CHIP_ID_VALUE        0xF9    /* Expected chip ID value */

/* Power Management */
#define MIC6200_PWR_MGMT_ADDR        0x40    /* Power management register */

/* Acceleration Data Registers */
#define MIC6200_ACCEL_X_LSB_ADDR     0x0E    /* X axis LSB register */
#define MIC6200_ACCEL_X_MSB_ADDR     0x0F    /* X axis MSB register */
#define MIC6200_ACCEL_Y_LSB_ADDR     0x10    /* Y axis LSB register */
#define MIC6200_ACCEL_Y_MSB_ADDR     0x11    /* Y axis MSB register */
#define MIC6200_ACCEL_Z_LSB_ADDR     0x12    /* Z axis LSB register */
#define MIC6200_ACCEL_Z_MSB_ADDR     0x13    /* Z axis MSB register */

/* Control Registers */
#define MIC6200_CTRL_REG1_ADDR      0x41    /* Control register 1 */
#define MIC6200_CTRL_REG2_ADDR      0x42    /* Control register 2 */
#define MIC6200_CTRL_REG3_ADDR      0x43    /* Control register 3 */
#define MIC6200_CTRL_REG4_ADDR      0x44    /* Control register 4 */
#define MIC6200_CTRL_REG5_ADDR      0x45    /* Control register 5 */
#define MIC6200_CTRL_REG6_ADDR      0x46    /* Control register 6 */
#define MIC6200_CTRL_REG7_ADDR      0x47    /* Control register 7 */
#define MIC6200_CTRL_REG8_ADDR      0x48    /* Control register 8 */

/* Page Select Register */
#define MIC6200_PAGE_SEL_ADDR       0xFF    /* Page select register */
#define MIC6200_PAGE_0_VALUE        0x00    /* Page 0 */
#define MIC6200_PAGE_1_VALUE        0x01    /* Page 1 */

/* MIC6200 ODR and Range Settings */
/* ODR Settings */
#define MIC6200_ODR_31_25HZ         0x04    /* 31.25Hz output data rate */
#define MIC6200_ODR_62_5HZ          0x05    /* 62.5Hz output data rate */
#define MIC6200_ODR_125HZ           0x06    /* 125Hz output data rate */
#define MIC6200_ODR_250HZ           0x07    /* 250Hz output data rate */
#define MIC6200_ODR_500HZ           0x08    /* 500Hz output data rate */
#define MIC6200_ODR_1000HZ          0x09    /* 1000Hz output data rate */
#define MIC6200_ODR_2000HZ          0x0A    /* 2000Hz output data rate */
#define MIC6200_ODR_4000HZ          0x0B    /* 4000Hz output data rate */

/* Range Settings */
#define MIC6200_RANGE_2G            0x00    /* ±2g range */
#define MIC6200_RANGE_4G            0x02    /* ±4g range */
#define MIC6200_RANGE_8G            0x04    /* ±8g range */
#define MIC6200_RANGE_16G           0x06    /* ±16g range */

/* FIFO Register */
#define MIC6200_FIFO_CTRL_ADDR       0x20    /* FIFO control register */
#define MIC6200_FIFO_STATUS_ADDR     0x21    /* FIFO status register */

/* Interrupt Register */
#define MIC6200_INT_CTRL_ADDR       0x16    /* Interrupt control register */
#define MIC6200_INT_STATUS_ADDR     0x17    /* Interrupt status register */

/* Self-test Register */
#define MIC6200_SELF_TEST_ADDR      0x60    /* Self-test register */

/* MIC6200 Register Values */
#define MIC6200_ENABLE_VALUE        0x01    /* Enable value */
#define MIC6200_DISABLE_VALUE       0x00    /* Disable value */

struct Mic6200DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* ACCEL_MIC6200_H */