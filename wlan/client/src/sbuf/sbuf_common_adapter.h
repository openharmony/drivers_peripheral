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

#ifndef SBUF_COMMON_ADAPTER_H
#define SBUF_COMMON_ADAPTER_H

#include "../wifi_common_cmd.h"
#include "hdf_io_service.h"
#include "hdf_sbuf.h"

int32_t SendCmdSync(const uint32_t cmd, struct HdfSBuf *reqData, struct HdfSBuf *respData);
struct HdfIoService *GetWifiService(void);
struct HdfIoService *InitWifiService(const char *serviceName);
void ReleaseWifiService(void);
int OnWiFiEvents(struct HdfDevEventlistener *listener,
    struct HdfIoService *service, uint32_t eventId, struct HdfSBuf *data);

#endif /* end of sbuf_common_adapter.h */
