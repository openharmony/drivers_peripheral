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
 
#ifndef WPA_HDI_UTIL_H
#define WPA_HDI_UTIL_H
 
#ifdef __cplusplus
extern "C" {
#endif
 
#define WPA_SUPPLICANT_NAME "wpa_supplicant"
#define CONFIG_ROOR_DIR "/data/service/el1/public/eth"
#define WPA_CTRL_OPEN_IFNAME "@abstract:"CONFIG_ROOR_DIR"/eth0"
#define START_CMD "wpa_supplicant -c"CONFIG_ROOR_DIR"/eth_wpa_supplicant.conf -Dwired -g"WPA_CTRL_OPEN_IFNAME
 
#ifdef __cplusplus
}
#endif
#endif
