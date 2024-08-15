/**
* Copyright (c) 2024 Bosch Sensortec GmbH. All rights reserved.
*
* gyro_bmi270.h as part of the * /chipsets subdirectory
* is dual licensed: you can use it either under the terms of
* the GPL, or the BSD license, at your option.
* See the LICENSE file in the root of this repository for complete details.
*/

#ifndef GYRO_BMI270_H
#define GYRO_BMI270_H

#include "sensor_gyro_driver.h"
#include "sensor_config_parser.h"

#define BMI270_GYR_DATA_FRAME_SIZE      6
#define BMI270_ONE_BYTE                 sizeof(uint8_t)
#define BMI270_TWO_BYTE                 sizeof(uint16_t)

// bus operation delay
#define BMI270_NORMAL_MODE_WRITE_DELAY_IN_US   4
#define BMI270_LP_MODE_WRITE_DELAY_IN_US       460

// feature operation delay
#define BMI270_RESET_DELAY_IN_MS               5
#define BMI270_LOAD_RAM_PATCH_DELAY_IN_MS      10

// bit definition
#define BMI270_GYR_POWER_BIT_POS_IN_PWR_CTRL_REG    1


#define BST_GET_VAL_BIT(val, bit)      (((val)>>(bit)) & 0x01)
#define BST_SET_VAL_BIT(val, bit)      ((val) | (1 << (bit)))
#define BST_CLR_VAL_BIT(val, bit)      ((val) & (~(1 << (bit))))

#define BMI270_GYRO_REGA_STATUS             0x03
/* GYRO DATA REGISTERS ADDR */
#define BMI270_GYRO_REGA_X_LSB_ADDR         0X12
#define BMI270_GYRO_REGA_X_MSB_ADDR         0X13
#define BMI270_GYRO_REGA_Y_LSB_ADDR         0X14
#define BMI270_GYRO_REGA_Y_MSB_ADDR         0X15
#define BMI270_GYRO_REGA_Z_LSB_ADDR         0X16
#define BMI270_GYRO_REGA_Z_MSB_ADDR         0X17
#define BMI270_STATUS_ADDR                  0x1B

/* GYRO ODR */
#define BMI270_GYRO_ODR_RESERVED            0x00
#define BMI270_GYRO_ODR_25HZ                0x06
#define BMI270_GYRO_ODR_50HZ                0x07
#define BMI270_GYRO_ODR_100HZ               0x08
#define BMI270_GYRO_ODR_200HZ               0x09
#define BMI270_GYRO_ODR_400HZ               0x0A
#define BMI270_GYRO_ODR_800HZ               0x0B
#define BMI270_GYRO_ODR_1600HZ              0x0C
#define BMI270_GYRO_ODR_3200HZ              0x0D

/* default HZ */
#define BMI270_GYRO_DEFAULT_ODR_100HZ       100
#define BMI270_GYRO_DEFAULT_ODR_25HZ        25

/* GYRO RANGE */
#define BMI270_GYRO_RANGE_2000DPS           0X00
#define BMI270_GYRO_RANGE_1000DPS           0X01
#define BMI270_GYRO_RANGE_500DPS            0X02
#define BMI270_GYRO_RANGE_250DPS            0X03
#define BMI270_GYRO_RANGE_125DPS            0X04

/* GYRO sensitivity */
#define BMI270_GYRO_SENSITIVITY_2000DPS     61

/* GYRO DATA READY */
#define BMI270_GYRO_DATA_READY_MASK         0x40
#define BMI26X_REGV_WHOAMI                  0x24
#define BMI270_REGA_INTERNAL_STATUS         0x21

#define BMI26X_REGA_GYRO_ODR                0x42
#define BMI26X_REGA_GYRO_RANGE              0x43

#define BMI26X_REGA_USR_TITAN_CTRL          0x59
#define BMI26X_REGA_USR_CONF_STREAM_IDX_LSB 0x5b
#define BMI26X_REGA_USR_CONF_STREAM_IN      0x5e

#define BMI270_REGA_PWR_CFG                 0x7C
#define BMI270_REGA_PWR_CTRL                0x7D
#define BMI26X_REGA_USR_CMD                 0x7E

#define BMI26X_CHECK_CONFIGURE_STATUS_TIMES 15

#define BMI26X_REGV_CMD_SOFT_RESET          0xB6

struct Bmi270DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* GYRO_BMI270_H */
