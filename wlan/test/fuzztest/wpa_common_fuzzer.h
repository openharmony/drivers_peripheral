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

#ifndef WPA_COMMON_FUZZER_H
#define WPA_COMMON_FUZZER_H
#include "hdf_log.h"
#include "v1_0/iwpa_callback.h"
#include "v1_0/iwpa_interface.h"
#include "securec.h"
#include <osal_mem.h>

#define HDF_LOG_TAG HDF_WIFI_CORE
#define IFNAMSIZ 16
constexpr int32_t OFFSET = 4;

uint32_t SetWpaDataSize(const uint32_t *dataSize);
uint32_t GetWpaDataSize(uint32_t *dataSize);
uint32_t Convert2Uint32(const uint8_t *ptr);
bool PreProcessRawData(const uint8_t *rawData, size_t size, uint8_t *tmpRawData, size_t tmpRawDataSize);

void FuzzWpaInterfaceScan(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceScanResult(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceAddNetwork(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceRemoveNetwork(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceDisableNetwork(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceSetNetwork(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceReconnect(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceDisconnect(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceSelectNetwork(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceEnableNetwork(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceSetPowerSave(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceAutoConnect(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceSaveConfig(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceWpsCancel(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceGetCountryCode(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceGetNetwork(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceBlocklistClear(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceSetSuspendMode(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceGetScanSsid(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceGetPskPassphrase(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceGetPsk(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceGetWepKey(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceGetWepTxKeyIdx(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceGetRequirePmf(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceSetCountryCode(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceListNetworks(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceWifiStatus(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceWpsPbcMode(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceWpsPinMode(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceRegisterEventCallback(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceUnregisterEventCallback(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceGetConnectionCapabilities(struct IWpaInterface *interface, const uint8_t *rawData);

typedef void (*FuzzWpaFuncs)(struct IWpaInterface *interface, const uint8_t *rawData);
#endif // WPA_COMMON_FUZZER_H
