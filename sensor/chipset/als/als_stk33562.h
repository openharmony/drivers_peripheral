/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef ALS_STK33562_H
#define ALS_STK33562_H

#include "sensor_als_driver.h"
#include "sensor_config_parser.h"


/* ALS DATA REGISTERS ADDR */
#define STK33562_ALS_D_MSB_ADDR 0X13
#define STK33562_ALS_D_LSB_ADDR 0X14

/* ALS Clear REGISTERS ADDR */
#define STK33562_ALS_C_MSB_ADDR 0X1B
#define STK33562_ALS_C_LSB_ADDR 0X1C

#define STK33562_STATUS_ADDR 0x10

#define STK33562_ALS_DATA_READY_MASK (1 << 7)

/* ALS TIME */
#define STK33562_TIME_25MSEC 25
#define STK33562_TIME_50MSEC 50
#define STK33562_TIME_100MSEC 100
#define STK33562_TIME_200MSEC 200
#define STK33562_TIME_400MSEC 400
#define STK33562_TIME_800MSEC 800
#define STK33562_TIME_1600MSEC 1600

/* ALS GAIN */
#define STK33562_GAIN_1X 1
#define STK33562_GAIN_4X 4
#define STK33562_GAIN_16X 16
#define STK33562_GAIN_64X 64


/* ALS TIME REG VALUE */
#define EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_0 0x00
#define EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_1 0x01
#define EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_2 0x02
#define EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_3 0x03
#define EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_4 0x04
#define EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_5 0x05
#define EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_6 0x06

/* ALS GAIN REG VALUE */
#define EXTENDED_ALS_GAIN_GROUP_ATTR_VALUE_0 0x00
#define EXTENDED_ALS_GAIN_GROUP_ATTR_VALUE_1 0x10
#define EXTENDED_ALS_GAIN_GROUP_ATTR_VALUE_2 0x20
#define EXTENDED_ALS_GAIN_GROUP_ATTR_VALUE_3 0x30

#define STK33562_ALS_MAX_VALUE 65535
#define STK33562_ALS_MIN_VALUE 6

/* ALS Lux/LSB系数扩大10000倍数，这边需要除去10000 */
#define STK33562_ALS_LUX_LSB_SCALE 100000

/* ALS Lux/LSB系数扩大10000倍数，这边需要除去10000 */
#define STK33562_ALS_MXL_SCALE 1000

enum ExtendedAlsTimeRegGroupIndex {
    EXTENDED_ALS_TIME_GROUP_INDEX_0 = 0,
    EXTENDED_ALS_TIME_GROUP_INDEX_1,
    EXTENDED_ALS_TIME_GROUP_INDEX_2,
    EXTENDED_ALS_TIME_GROUP_INDEX_3,
    EXTENDED_ALS_TIME_GROUP_INDEX_4,
    EXTENDED_ALS_TIME_GROUP_INDEX_5,
    EXTENDED_ALS_TIME_GROUP_INDEX_6,
    EXTENDED_ALS_TIME_GROUP_INDEX_MAX,
};

enum ExtendedAlsGainRegGroupIndex {
    EXTENDED_ALS_GAIN_GROUP_INDEX_0 = 0,
    EXTENDED_ALS_GAIN_GROUP_INDEX_1,
    EXTENDED_ALS_GAIN_GROUP_INDEX_2,
    EXTENDED_ALS_GAIN_GROUP_INDEX_3,
    EXTENDED_ALS_GAIN_GROUP_INDEX_MAX,
};

typedef struct {
    uint32_t time;      /* 积分时间 */
    uint32_t gain;      /* 增益 */
    uint32_t luxLsb;    /* 对应Lux/LSB系数 */
} AlsLuxLsbMap;

enum AlsStk33562LightPart {
    ALS_STK33562_D_LSB = 0,
    ALS_STK33562_D_MSB = 1,
    ALS_STK33562_C_LSB = 2,
    ALS_STK33562_C_MSB = 3,
    ALS_STK33562_BUF = 4,
};


enum AlsStk33562Num {
    ALS_STK33562_DATA = 0,
    ALS_STK33562_CLEAR = 1,
    ALS_STK33562_NUM = 2,
};


int32_t DetectAlsStk33562Chip(struct SensorCfgData *data);


struct Stk33562AlsData {
    int32_t als;
    int32_t clear;
};

struct Stk33562DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

#endif /* ALS_STK33562_H */
