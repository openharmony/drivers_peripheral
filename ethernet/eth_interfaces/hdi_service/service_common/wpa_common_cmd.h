/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef WPA_COMMON_CMD_H
#define WPA_COMMON_CMD_H
 
#include <pthread.h>
#include <hdf_remote_service.h>
#include <stdio.h>
#include <stdlib.h>
 
#include "../ethernet_impl.h"
#include "utils/common.h"
 
#define MAX_WPA_MAIN_ARGC_NUM 20
#define MAX_WPA_MAIN_ARGV_LEN 128
 
struct WpaMainParam {
    int argc;
    char argv[MAX_WPA_MAIN_ARGC_NUM][MAX_WPA_MAIN_ARGV_LEN];
};
 
int32_t EthStartEap(struct IEthernet *self, const char *ifName);
int32_t EthStopEap(struct IEthernet *self, const char *ifName);
int32_t EthRegisterEapEventCallback(struct IEthernet *self, struct IEthernetCallback *cbFunc, const char *ifName);
int32_t EthUnregisterEapEventCallback(struct IEthernet *self, struct IEthernetCallback *cbFunc, const char *ifName);
int32_t EthEapShellCmd(struct IEthernet *self, const char *ifName, const char *cmd);
 
#endif
