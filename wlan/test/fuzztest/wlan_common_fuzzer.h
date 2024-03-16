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

#ifndef WLAN_COMMON_FUZZER_H
#define WLAN_COMMON_FUZZER_H
#include "hdf_log.h"
#include "v1_3/iwlan_interface.h"
#include "v1_3/wlan_types.h"
#include "wifi_hal_base_feature.h"
#include "securec.h"
#include <osal_mem.h>

#define HDF_LOG_TAG HDF_WIFI_CORE
#define IFNAMSIZ 16
constexpr int32_t OFFSET = 4;

uint32_t SetWlanDataSize(const uint32_t *dataSize);
uint32_t GetWlanDataSize(uint32_t *dataSize);
uint32_t Convert2Uint32(const uint8_t *ptr);
bool PreProcessRawData(const uint8_t *rawData, size_t size, uint8_t *tmpRawData, size_t tmpRawDataSize);
void FuzzGetChipId(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzGetDeviceMacAddress(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzGetFeatureType(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzGetFreqsWithBand(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzGetNetworkIfaceName(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzSetMacAddress(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzSetTxPower(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzGetPowerMode(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzSetPowerMode(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzGetIfNamesByChipId(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzResetDriver(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzStartChannelMeas(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzSetProjectionScreenParam(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzWifiSendCmdIoctl(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzResetToFactoryMacAddress(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzGetFeatureByIfName(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzGetStaInfo(struct IWlanInterface *interface, const uint8_t *rawData);
void FuzzGetChannelMeasResult(struct IWlanInterface *interface, const uint8_t *rawData);

typedef void (*FuzzWlanFuncs)(struct IWlanInterface *interface, const uint8_t *rawData);
#endif // WLAN_COMMON_FUZZER_H
