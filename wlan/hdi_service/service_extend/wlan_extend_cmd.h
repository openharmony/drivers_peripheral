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
#ifndef WLAN_EXTEND_CMD_H
#define WLAN_EXTEND_CMD_H
#include "../wlan_impl.h"

int32_t WlanInterfaceStartChannelMeas(struct IWlanInterface *self, const char *ifName,
    const struct MeasChannelParam *measChannelParam);
int32_t WlanInterfaceGetChannelMeasResult(struct IWlanInterface *self, const char *ifName,
    struct MeasChannelResult *measChannelResult);
int32_t WlanInterfaceWifiSendCmdIoctl(struct IWlanInterface *self, const char *ifName, int32_t cmdId,
    const int8_t *paramBuf, uint32_t paramBufLen);
int32_t WlanInterfaceRegisterHid2dCallback(Hid2dCallbackFunc func, const char *ifName);
int32_t WlanInterfaceUnregisterHid2dCallback(Hid2dCallbackFunc func, const char *ifName);
int32_t WlanExtendInterfaceWifiConstruct(void);
int32_t WlanExtendInterfaceWifiDestruct(void);
#endif
