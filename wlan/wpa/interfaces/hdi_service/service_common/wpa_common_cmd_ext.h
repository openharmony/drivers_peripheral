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
#ifndef WPA_COMMON_CMD_EXT_H
#define WPA_COMMON_CMD_EXT_H


#include "../wpa_impl.h"
#include <hdf_remote_service.h>
#include "utils/common.h"
#include "wpa_supplicant_hal.h"

int32_t WpaInterfaceStart(struct IWpaInterface *self);
int32_t WpaInterfaceStop(struct IWpaInterface *self);
int32_t WpaInterfaceAddWpaIface(struct IWpaInterface *self, const char *ifName, const char *confName) ;
int32_t WpaInterfaceRemoveWpaIface(struct IWpaInterface *self, const char *ifName);
int32_t WpaInterfaceScan(struct IWpaInterface *self, const char *ifName);
int32_t WpaInterfaceScanResult(struct IWpaInterface *self, const char *ifName, unsigned char *resultBuf,
    uint32_t *resultBufLen);
const char *MacToStr(const u8 *addr);
#endif
