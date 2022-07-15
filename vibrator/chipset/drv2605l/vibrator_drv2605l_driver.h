/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#ifndef DRV2605L_DRIVER_H
#define DRV2605L_DRIVER_H

#include "hdf_device_desc.h"

#define I2C_READ_MSG_NUM           2
#define I2C_READ_MSG_ADDR_IDX      0
#define I2C_READ_MSG_VALUE_IDX     1

#define DRV2605L_ADDR_WIDTH_1_BYTE        1 // 8 bit
#define DRV2605L_ADDR_WIDTH_2_BYTE        2 // 16 bit

#define I2C_WRITE_MSG_NUM  1
#define I2C_REG_BUF_LEN    4
#define I2C_BYTE_MASK      0xFF
#define I2C_BYTE_OFFSET    8

#define DRV2605_REG_MODE 0x01         // Mode register
#define DRV2605_MODE_REALTIME 0x05    // Real-time playback (RTP) mode
#define DRV2605_MODE_STANDBY 0x45     // Software standby mode

#define DRV2605_REG_CONTROL3 0x1D     // Control3 Register
#define DRV2605_MODE_OPEN_LOOP 0xA9   // Open Loop

#define DRV2605_REG_FEEDBACK 0x1A // Feedback control register
#define DRV2605_MODE_LRA 0xB6 // LRA Mode

#define DRV2605_REG_RTPIN 0x02 // Real-time playback input register
#define DRV2605_REG_LRARESON 0x20 // LRA open loop period

#define INTENSITY_MAPPING_VALUE(value) {0XA8 + ((value) * (0XFF - 0XA8)) / 100}

#define FREQUENCY_MAPPING_VALUE(value) {1000000 / (98.46 * (value))}

enum Drv2605lConfigValueIndex {
    DRV2605L_ADDR_INDEX,
    DRV2605L_VALUE_INDEX,
    DRV2605L_VALUE_BUTT,
};

struct Drv2605lDriverData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    const struct DeviceResourceNode *root;
    struct VibratorCfgData *drv2605lCfgData;
};

#endif /* DRV2605L_DRIVER_H */