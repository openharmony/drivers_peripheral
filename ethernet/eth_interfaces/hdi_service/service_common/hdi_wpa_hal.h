/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
 
#ifndef HDI_WPA_HAL_H
#define HDI_WPA_HAL_H
 
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>
 
#include "wpa_hdi_util.h"
#include "v1_0/iethernet.h"
 
#ifdef __cplusplus
extern "C" {
#endif
 
typedef struct WpaCtrl {
    struct wpa_ctrl *pSend;
    struct wpa_ctrl *pRecv;
} WpaCtrl;
 
typedef struct EthWpaInstance EthWpaInstance;
struct EthWpaInstance {
    WpaCtrl staCtrl;
    pthread_t tid;
    int (*wpaCliConnect)(EthWpaInstance *p);
    void (*wpaCliClose)(EthWpaInstance *p);
    int (*wpaCliTerminate)();
    int (*wpaCliCmdSetNetwork)(EthWpaInstance *p, const char *ifName, const char *name, const char *value);
    int (*wpaCliCmdStaShellCmd)(EthWpaInstance *p, const char *ifName, const char *params);
};
 
int InitWpaCtrl(WpaCtrl *pCtrl, const char *ctrlPath);
void ReleaseWpaCtrl(WpaCtrl *pCtrl);
int WpaCliCmd(const char *cmd, char *buf, size_t bufLen);
 
void InitEthWpaGlobalInstance(void);
void ReleaseEthWpaGlobalInstance(void);
EthWpaInstance *GetEthWpaGlobalInstance(void);
 
#ifdef __cplusplus
}
#endif
#endif
