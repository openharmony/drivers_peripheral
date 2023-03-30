/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UINPUT_I2C_OPS_H
#define UINPUT_I2C_OPS_H

#include "hdf_types.h"
#include "i2c_if.h"

typedef struct {
    uint16_t busNum;
    uint16_t addr;
} I2cConfig;

typedef struct {
    DevHandle *i2cHandle;
    I2cConfig i2cCfg;
} InputI2cClient;

int InputI2cRead(const InputI2cClient *client, uint8_t *writeBuf, uint32_t writeLen, uint8_t *readBuf,
    uint32_t readLen);
int InputI2cWrite(const InputI2cClient *client, uint8_t *writeBuf, uint32_t len);

#endif // UINPUT_I2C_OPS_H