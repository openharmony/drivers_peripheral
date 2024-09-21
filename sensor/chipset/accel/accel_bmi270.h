/**
* Copyright (c) 2024 Bosch Sensortec GmbH. All rights reserved.
*
* accel_bmi270.h as part of the * /chipsets subdirectory
* is dual licensed: you can use it either under the terms of
* the GPL, or the BSD license, at your option.
* See the LICENSE file in the root of this repository for complete details.
*/

#ifndef ACC_BMI270_H
#define ACC_BMI270_H

#include "sensor_accel_driver.h"
#include "sensor_config_parser.h"

#define BMI270_ACC_DATA_FRAME_SIZE      6
#define BMI270_ONE_BYTE                 sizeof(uint8_t)
#define BMI270_TWO_BYTE                 sizeof(uint16_t)

// bus operation delay
#define BMI270_NORMAL_MODE_WRITE_DELAY_IN_US   4
#define BMI270_LP_MODE_WRITE_DELAY_IN_US       460

// feature operation delay
#define BMI270_RESET_DELAY_IN_MS               5
#define BMI270_LOAD_RAM_PATCH_DELAY_IN_MS      10

// bit definition
#define BMI270_ACC_POWER_BIT_POS_IN_PWR_CTRL_REG    2

#define BST_GET_VAL_BIT(val, bit) (((val) >> (bit)) & 0x01)
#define BST_GET_VAL_BITBLOCK(val, start, end) (((val) >> (start)) & ((1 << (end - start + 1))-1))

#define BST_SET_VAL_BIT(val, bit)      (val | (1 << (bit)))
#define BST_CLR_VAL_BIT(val, bit)      (val & (~(1 << (bit))))

#define BMI270_ACCEL_REGA_STATUS                  0X03
#define BMI270_ACCEL_REGA_X_LSB_ADDR              0X0C
#define BMI270_ACCEL_REGA_X_MSB_ADDR              0X0D
#define BMI270_ACCEL_REGA_Y_LSB_ADDR              0X0E
#define BMI270_ACCEL_REGA_Y_MSB_ADDR              0X0F
#define BMI270_ACCEL_REGA_Z_LSB_ADDR              0X10
#define BMI270_ACCEL_REGA_Z_MSB_ADDR              0X11
#define BMI270_ACCEL_REGA_INT_STATUS              0X1D

/* ACCEL ODR */
#define BMI270_ACCEL_REGA_ODR_RESERVED            0x00
#define BMI270_ACCEL_REGA_ODR_0_78HZ              0x01
#define BMI270_ACCEL_REGA_ODR_1_56HZ              0x02
#define BMI270_ACCEL_REGA_ODR_3_12HZ              0x03
#define BMI270_ACCEL_REGA_ODR_6_25HZ              0x04
#define BMI270_ACCEL_REGA_ODR_12_5HZ              0x05
#define BMI270_ACCEL_REGA_ODR_25HZ                0x06
#define BMI270_ACCEL_REGA_ODR_50HZ                0x07
#define BMI270_ACCEL_REGA_ODR_100HZ               0x08
#define BMI270_ACCEL_REGA_ODR_200HZ               0x09
#define BMI270_ACCEL_REGA_ODR_400HZ               0x0A
#define BMI270_ACCEL_REGA_ODR_800HZ               0x0B
#define BMI270_ACCEL_REGA_ODR_1600HZ              0x0C
#define BMI270_ACCEL_REGA_ODR_RESERVED0           0x0D
#define BMI270_ACCEL_REGA_ODR_RESERVED1           0x0E
#define BMI270_ACCEL_REGA_ODR_RESERVED2           0x0F


#define BMI270_REGA_INTERNAL_STATUS     0x21

#define BMI26X_REGA_ACC_ODR             0x40
#define BMI26X_REGA_ACC_RANGE           0x41
#define BMI26X_REGA_USR_ERR_REG_MASK    0x52
#define BMI26X_REGA_USR_INT1_IO_CTRL    0x53
#define BMI26X_REGA_USR_INT2_IO_CTRL    0x54
#define BMI26X_REGA_USR_INT_LATCH       0x55
#define BMI26X_REGA_USR_INT1_MAP        0x56
#define BMI26X_REGA_USR_INT2_MAP        0x57
#define BMI26X_REGA_USR_INT_MAP_HW      0x58
#define BMI26X_REGA_USR_TITAN_CTRL      0x59
#define BMI26X_REGA_USR_CONF_STREAM_IDX_LSB 0x5b
#define BMI26X_REGA_USR_CONF_STREAM_IN  0x5e
#define BMI26X_REGA_USR_INTERNAL_ERROR  0x5f

#define BMI270_REGA_PWR_CFG             0x7C
#define BMI270_REGA_PWR_CTRL            0x7D
#define BMI26X_REGA_USR_CMD             0x7E

#define BMI26X_REGV_WHOAMI              0x24
#define BMI26X_REGV_CMD_SOFT_RESET      0xB6

/* default HZ */
#define BMI270_ACCEL_DEFAULT_ODR_100HZ       100   /*hw defualt value @0x8*/
#define BMI270_ACCEL_DEFAULT_ODR_25HZ        25

#define BMI26X_CHECK_CONFIGURE_STATUS_TIMES  15
#define BMI270_ACCEL_DATA_READY_MASK         0x80

#define BMI270_ACC_ODR_FILTER_DEFAULT        0xA0

/* ACC sensitivity */
#define BMI270_ACC_SENSITIVITY_2G            61
#define BMI270_ACC_SENSITIVITY_4G            122
#define BMI270_ACC_SENSITIVITY_8G            244
#define BMI270_ACC_SENSITIVITY_16G           488

struct Bmi270DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* ACC_BMI270_H */
