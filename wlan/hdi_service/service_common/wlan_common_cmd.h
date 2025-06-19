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
#ifndef WLAN_COMMON_CMD_H
#define WLAN_COMMON_CMD_H
 
#include "../wlan_impl.h"

#define WLAN_MAJOR_VER 1
#define WLAN_MINOR_VER 3
int32_t WlanInterfaceStart(struct IWlanInterface *self);
int32_t WlanInterfaceStop(struct IWlanInterface *self);
int32_t WlanInterfaceCreateFeature(struct IWlanInterface *self, int32_t type, struct HdfFeatureInfo *ifeature);
int32_t WlanInterfaceDestroyFeature(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature);
int32_t WlanInterfaceGetAssociatedStas(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    struct HdfStaInfo *staInfo, uint32_t *staInfoLen, uint32_t *num);
int32_t WlanInterfaceGetChipId(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature, uint8_t *chipId);
int32_t WlanInterfaceGetDeviceMacAddress(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    uint8_t *mac, uint32_t *macLen, uint8_t len);
int32_t WlanInterfaceGetFeatureByIfName(struct IWlanInterface *self, const char *ifName,
    struct HdfFeatureInfo *ifeature);
int32_t WlanInterfaceGetFeatureType(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    int32_t *featureType);
int32_t WlanInterfaceGetFreqsWithBand(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    const struct HdfWifiInfo *wifiInfo, int32_t *freq, uint32_t *freqLen);
int32_t WlanInterfaceGetIfNamesByChipId(struct IWlanInterface *self, uint8_t chipId, char *ifName,
    uint32_t ifNameLen, uint32_t *num);
int32_t WlanInterfaceGetNetworkIfaceName(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    char *ifName, uint32_t ifNameLen);
int32_t WlanInterfaceGetSupportCombo(struct IWlanInterface *self, uint64_t *combo);
int32_t WlanInterfaceGetSupportFeature(struct IWlanInterface *self, uint8_t *supType, uint32_t *supTypeLen);
int32_t WlanInterfaceRegisterEventCallback(struct IWlanInterface *self, struct IWlanCallback *cbFunc,
    const char *ifName);
int32_t WlanInterfaceUnregisterEventCallback(struct IWlanInterface *self, struct IWlanCallback *cbFunc,
    const char *ifName);
int32_t WlanInterfaceResetDriver(struct IWlanInterface *self, uint8_t chipId, const char *ifName);
int32_t WlanInterfaceSetCountryCode(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    const char *code, uint32_t len);
int32_t WlanInterfaceSetMacAddress(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    const uint8_t *mac, uint32_t macLen);
int32_t WlanInterfaceSetScanningMacAddress(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    const uint8_t *scanMac, uint32_t scanMacLen);
int32_t WlanInterfaceSetTxPower(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature, int32_t power);
int32_t WlanInterfaceGetNetDevInfo(struct IWlanInterface *self, struct HdfNetDeviceInfoResult *netDeviceInfoResult);
int32_t WlanInterfaceStartScan(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    const struct HdfWifiScan *scan);
int32_t WlanInterfaceGetPowerMode(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature, uint8_t *mode);
int32_t WlanInterfaceSetPowerMode(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature, uint8_t mode);
int32_t WlanInterfaceSetProjectionScreenParam(struct IWlanInterface *self, const char *ifName,
    const struct ProjectionScreenCmdParam *param);
int32_t WlanInterfaceGetStaInfo(struct IWlanInterface *self, const char *ifName, struct WifiStationInfo *info,
    const uint8_t *mac, uint32_t macLen);
int32_t WlanInterfaceStartPnoScan(struct IWlanInterface *self, const char *ifName,
    const struct PnoSettings *pnoSettings);
int32_t WlanInterfaceStopPnoScan(struct IWlanInterface *self, const char *ifName);
int32_t WlanInterfaceGetSignalPollInfo(struct IWlanInterface *self, const char *ifName,
    struct SignalPollResult *signalResult);
int32_t WlanInterfaceGetApBandwidth(struct IWlanInterface *self, const char *ifName,
    uint8_t *bandwidth);
int32_t WlanInterfaceResetToFactoryMacAddress(struct IWlanInterface *self, const char *ifName);
int32_t WlanInterfaceSendActionFrame(struct IWlanInterface *self, const char *ifName, uint32_t freq,
    const uint8_t *frameData, uint32_t frameDataLen);
int32_t WlanInterfaceRegisterActionFrameReceiver(struct IWlanInterface *self, const char *ifName,
    const uint8_t *match, uint32_t matchLen);
int32_t WlanInterfaceGetCoexChannelList(struct IWlanInterface *self, const char *ifName,
    uint8_t *paramBuf, uint32_t *paramBufLen);
int32_t WlanInterfaceSetPowerSaveMode(struct IWlanInterface *self, const char *ifName, int32_t frequency,
    int32_t mode);
int32_t WlanInterfaceSetDpiMarkRule(struct IWlanInterface *self, int32_t uid, int32_t protocol, int32_t enable);
int32_t WlanInterfaceWifiConstruct(void);
int32_t WlanInterfaceWifiDestruct(void);
int32_t WlanGetVersion(struct IWlanInterface *self, uint32_t *majorVer, uint32_t *minorVer);
#endif
