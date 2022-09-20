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
#include "v1_0/iwlan_interface.h"
#include "wifi_hal.h"
#include "wlan_common_cmd.h"

static struct IWiFi *g_wifi = NULL;

int32_t WlanInterfaceStartChannelMeas(struct IWlanInterface *self, const char *ifName,
    const struct MeasChannelParam *measChannelParam)
{
    int32_t ret;

    (void)self;
    if (ifName == NULL || measChannelParam == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL) {
        HDF_LOGE("%{public}s g_wifi is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->startChannelMeas(ifName, (const struct MeasParam *)measChannelParam);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: start channel meas failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceGetChannelMeasResult(struct IWlanInterface *self, const char *ifName,
    struct MeasChannelResult *measChannelResult)
{
    int32_t ret;

    (void)self;
    if (ifName == NULL || measChannelResult == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL) {
        HDF_LOGE("%{public}s g_wifi is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->getChannelMeasResult(ifName, (struct MeasResult *)measChannelResult);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get channel meas result failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceWifiSendCmdIoctl(struct IWlanInterface *self, const char *ifName, int32_t cmdId,
    const int8_t *paramBuf, uint32_t paramBufLen)
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
    ret = g_wifi->sendCmdIoctl(ifName, cmdId, paramBuf, paramBufLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: send ioctl command failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceRegisterHid2dCallback(Hid2dCallbackFunc func, const char *ifName)
{
    int ret;

    if (func == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL) {
        HDF_LOGE("%{public}s g_wifi is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->registerHid2dCallback(func, ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Register hid2d callback failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceUnregisterHid2dCallback(Hid2dCallbackFunc func, const char *ifName)
{
    int ret;

    if (func == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL) {
        HDF_LOGE("%{public}s g_wifi is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->unregisterHid2dCallback(func, ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Unregister hid2d callback failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanExtendInterfaceWifiConstruct(void)
{
    int32_t ret;
    ret = WifiConstruct(&g_wifi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s construct WiFi failed! error code: %{public}d", __func__, ret);
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
