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
 
#ifndef ETHERNET_EAP_CLIENT_H
#define ETHERNET_EAP_CLIENT_H
 
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
 
#define IFNAMSIZE 10
 
struct EthEapCallback {
    char ifName[IFNAMSIZE + 1];
    struct IEthernetCallback* callback;
};
 
void EthEapClientEventReport(const char *ifName, const char *data);
int32_t EthEapClientRegisterCallback(struct IEthernetCallback* callback, const char *ifName);
int32_t EthEapClientUnregisterCallback(struct IEthernetCallback* callback, const char *ifName);
void EthEapClientReleaseCallback(void);
 
#ifdef __cplusplus
}
#endif
#endif // ETHERNET_EAP_CLIENT_H
