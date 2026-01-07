/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef MAGNETIC_VCM1193L_H
#define MAGNETIC_VCM1193L_H

#include "sensor_config_parser.h"
#include "sensor_magnetic_driver.h"

#define VCM1193L_MAGNETIC_SENSITIVITY_8G 30
#define VCM1193L_MAGNETIC_UT_TO_NT 1000


/* ctrl reg addr */
#define VCM1193L_CTRL_REG_1 0X0A
#define VCM1193L_CTRL_REG_2 0X0B
#define VCM1193L_CHIP_ID_REG 0X0C

#define VCM1193L_CHIP_ID_VALUE 0X82

#define VCM1193L_MAGNETIC_X_LSB_ADDR 0X00
#define VCM1193L_MAGNETIC_X_MSB_ADDR 0X01
#define VCM1193L_MAGNETIC_Y_LSB_ADDR 0X02
#define VCM1193L_MAGNETIC_Y_MSB_ADDR 0X03
#define VCM1193L_MAGNETIC_Z_LSB_ADDR 0X04
#define VCM1193L_MAGNETIC_Z_MSB_ADDR 0X05

#define VCM1193L_ODR_200HZ 0X00
#define VCM1193L_ODR_100HZ 0X01
#define VCM1193L_ODR_50HZ 0X02
#define VCM1193L_ODR_10HZ 0X03

#define VCM1193L_MODE_STANDBY 0X00
#define VCM1193L_MODE_NORMAL 0X01

#define VCM1193L_SOFT_RST_NORMAL 0X00
#define VCM1193L_SOFT_RST_TRIGGER 0X80

#define VCM1193L_SET_RESET_AUTO 0X00
#define VCM1193L_SET_RESET_ONLY_SET 0X01
#define VCM1193L_SET_RESET_DISABLE 0X02
#define VCM1193L_SET_RESET_RESERVED 0X03


int32_t DetectMagneticVcm1193lChip(struct SensorCfgData *data);

struct Vcm1193lDrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* MAGNETIC_VCM1193L_H */
