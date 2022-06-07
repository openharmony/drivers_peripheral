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
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <osal_mem.h>
#include "v1_0/wlan_interface_service.h"
#include "wifi_hal.h"
#include "wlan_common_cmd.h"

static struct IWiFi *g_wifi = NULL;

int32_t WlanInterfaceStartChannelMeas(struct IWlanInterface *self, const char *ifName, int32_t commandId,
    const int32_t *paramBuf, uint32_t paramBufLen)
{
    int32_t ret;

    (void)self;
    if (ifName == NULL || paramBuf == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL) {
        HDF_LOGE("%{public}s g_wifi is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->startChannelMeas(ifName, commandId, paramBuf, paramBufLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: start channel meas failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceGetChannelMeasResult(struct IWlanInterface *self, const char *ifName, int32_t commandId,
    uint32_t *paramBuf, uint32_t *paramBufLen)
{
    int32_t ret;

    (void)self;
    if (ifName == NULL || paramBuf == NULL || paramBufLen == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL) {
        HDF_LOGE("%{public}s g_wifi is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->getChannelMeasResult(ifName, commandId, paramBuf, paramBufLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get channel meas result failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanExtendInterfaceWifiConstruct(void)
{
    int32_t ret;
    ret = WifiConstruct(&g_wifi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s contruct WiFi failed! error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanExtendInterfaceWifiDestruct(void)
{
    int32_t ret;
    ret = WifiDestruct(&g_wifi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s destruct WiFi failed! error code: %{public}d", __func__, ret);
    }
    return ret;
}
