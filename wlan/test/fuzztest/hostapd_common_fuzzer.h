/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef HOSTAPD_COMMON_FUZZER_H
#define HOSTAPD_COMMON_FUZZER_H
#include "hdf_log.h"
#include "v1_0/ihostapd_callback.h"
#include "v1_0/ihostapd_interface.h"
#include "securec.h"
#include <osal_mem.h>
//HDF_WPA_CORE
#define HDF_LOG_TAG
#define IFNAMSIZ 16
constexpr int32_t OFFSET = 4;

uint32_t SetWpaDataSize(const uint32_t *dataSize);
uint32_t GetWpaDataSize(uint32_t *dataSize);
uint32_t Convert2Uint32(const uint8_t *ptr);
bool PreProcessRawData(const uint8_t *rawData, size_t size, uint8_t *tmpRawData, size_t tmpRawDataSize);

void FuzzHostapdInterfaceStartAp(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceStopAp(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceEnableAp(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceDisableAp(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceSetApPasswd(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceSetApName(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceSetApBand(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceSetAp80211n(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceSetApWmm(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceSetApChannel(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceSetApMaxConn(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceSetMacFilter(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceDelMacFilter(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceGetStaInfos(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceReloadApConfigInfo(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceDisassociateSta(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceRegisterEventCallback(struct IHostapdInterface *interface, const uint8_t *rawData);
void FuzzHostapdInterfaceUnregisterEventCallback(struct IHostapdInterface *interface, const uint8_t *rawData);

#endif // WPA_COMMON_FUZZER_H
