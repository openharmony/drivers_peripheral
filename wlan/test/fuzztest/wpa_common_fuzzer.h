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
#include "v1_1/iwpa_callback.h"
#include "v1_1/iwpa_interface.h"
#include "securec.h"
#include <osal_mem.h>

#define HDF_LOG_TAG
#define IFNAMSIZ 16
constexpr int32_t OFFSET = 4;

uint32_t SetWpaDataSize(const uint32_t *dataSize);
uint32_t GetWpaDataSize(uint32_t *dataSize);
uint32_t Convert2Uint32(const uint8_t *ptr);
bool PreProcessRawData(const uint8_t *rawData, size_t size, uint8_t *tmpRawData, size_t tmpRawDataSize);

/* **********Wpa Interface********** */
void FuzzWpaInterfaceStart(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceStop(struct IWpaInterface *interface, const uint8_t *rawData);
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
void FuzzWpaInterfaceAddWpaIface(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceRemoveWpaIface(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceReassociate(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceStaShellCmd(struct IWpaInterface *interface, const uint8_t *rawData);


/* **********P2p Interface********** */
void FuzzWpaInterfaceP2pSetSsidPostfixName(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetWpsDeviceType(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetWpsConfigMethods(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetGroupMaxIdle(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetWfdEnable(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetPersistentReconnect(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetWpsSecondaryDeviceType(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetupWpsPbc(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetupWpsPin(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetPowerSave(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetDeviceName(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetWfdDeviceConfig(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetRandomMac(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pStartFind(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetExtListen(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetListenChannel(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pProvisionDiscovery(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pAddGroup(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pAddService(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pRemoveService(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pStopFind(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pFlush(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pFlushService(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pRemoveNetwork(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetGroupConfig(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pInvite(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pReinvoke(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pGetDeviceAddress(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pReqServiceDiscovery(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pCancelServiceDiscovery(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pRespServerDiscovery(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pConnect(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pHid2dConnect(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSetServDiscExternal(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pRemoveGroup(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pCancelConnect(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pGetGroupConfig(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pAddNetwork(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pGetPeer(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pGetGroupCapability(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pListNetworks(struct IWpaInterface *interface, const uint8_t *rawData);
void FuzzWpaInterfaceP2pSaveConfig(struct IWpaInterface *interface, const uint8_t *rawData);

#endif // WPA_COMMON_FUZZER_H