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

#ifndef HDF_AUDIO_PNP_SERVER_H
#define HDF_AUDIO_PNP_SERVER_H

#include "hdf_types.h"

/* serverName is object service; pnpInfo is send pnp report info; cmd is dispatch id */
int32_t AudioPnpStatusSend(const char *serverName, const char *pnpInfo, const int cmd);
/* statusInfo is update new info */
int32_t AudioPnpUpdateInfo(const char *statusInfo);

#endif
