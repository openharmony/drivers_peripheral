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

#include <stdlib.h>

#include "hdf_log.h"
#include "securec.h"
#include "sbuf_common_adapter.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

struct HdfIoService *g_wifiService = NULL;

struct HdfIoService *InitWifiService(const char *serviceName)
{
    g_wifiService = HdfIoServiceBind(serviceName);
    return g_wifiService;
}

struct HdfIoService *GetWifiService(void)
{
    return g_wifiService;
}

void ReleaseWifiService(void)
{
    if (g_wifiService != NULL) {
        HdfIoServiceRecycle(g_wifiService);
        g_wifiService = NULL;
    }
}

int32_t SendCmdSync(const uint32_t cmd, struct HdfSBuf *reqData, struct HdfSBuf *respData)
{
    if (reqData == NULL) {
        HDF_LOGE("%s: params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (g_wifiService == NULL || g_wifiService->dispatcher == NULL ||
        g_wifiService->dispatcher->Dispatch == NULL) {
        HDF_LOGE("%s:bad remote service found!", __FUNCTION__);
        return RET_CODE_MISUSE;
    }
    int32_t ret = g_wifiService->dispatcher->Dispatch(&g_wifiService->object, cmd, reqData, respData);
    HDF_LOGI("%s: cmd=%u, ret=%d", __FUNCTION__, cmd, ret);
    return ret;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif