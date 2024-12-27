/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DDK_SYSFS_DEVICE_H
#include <stdint.h>

#include "hdf_usb_pnp_manage.h"
#ifdef __cplusplus
extern "C" {
#endif
#define SYSFS_DEVICES_DIR "/sys/bus/usb/devices/"

typedef struct DevInterfaceInfo {
    uint32_t busNum;
    uint32_t devNum;
    uint8_t  intfNum;
} DevInterfaceInfo;

uint64_t DdkSysfsMakeDevAddr(uint32_t busNum, uint32_t devNum);
int32_t DdkSysfsGetDevice(const char *deviceDir, struct UsbPnpNotifyMatchInfoTable *device);
int32_t DdkSysfsGetDevNodePath(DevInterfaceInfo *devInfo, const char *prefix, char *buff, uint32_t buffSize);
#ifdef __cplusplus
}
#endif
#define DDK_SYSFS_DEVICE_H
#endif // DDK_SYSFS_DEVICE_H