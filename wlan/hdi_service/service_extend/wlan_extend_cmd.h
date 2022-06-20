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

int32_t WlanInterfaceStartChannelMeas(struct IWlanInterface *self, const char* ifName, int32_t commandId,
    const int32_t* paramBuf, uint32_t paramBufLen);
int32_t WlanInterfaceGetChannelMeasResult(struct IWlanInterface *self, const char* ifName, int32_t commandId,
    uint32_t* paramBuf, uint32_t* paramBufLen);
int32_t WlanInterfaceRegisterHmlCallback(NotifyMessage func, const char *ifName);
int32_t WlanInterfaceUnregisterHmlCallback(NotifyMessage func, const char *ifName);
int32_t WlanInterfaceGetCoexChannelList(struct IWlanInterface *self, const char* ifName, struct CoexChannelList *data);
int32_t WlanInterfaceSendHmlCmd(struct IWlanInterface *self, const char* ifName, const struct CmdData* data);
int32_t WlanExtendInterfaceWifiConstruct(void);
int32_t WlanExtendInterfaceWifiDestruct(void);
#endif
