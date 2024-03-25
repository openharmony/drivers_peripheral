/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <hdf_load_vdi.h>
#include <osal_time.h>
#include <osal_mem.h>
#include "v1_3/iwlan_interface.h"
#include "wifi_hal.h"
#include "wlan_common_cmd.h"
#include "wlan_extend_cmd_vdi.h"

#define VDI_VERSION_ONE 1

struct WlanExtendInterfaceVdi *g_wlanExtendVdiImpl = NULL;
struct HdfVdiObject *g_vdi = NULL;

static void CloseVdi(void)
{
    if (g_vdi != NULL) {
        HdfCloseVdi(g_vdi);
        g_vdi = NULL;
    }
}

static int32_t InitWlanExtendVdiImpl()
{
    uint32_t version = 0;
    g_vdi = HdfLoadVdi(WLAN_EXTEND_VDI_LIBNAME);
    if (g_vdi == NULL || g_vdi->vdiBase == NULL) {
        HDF_LOGE("%{public}s: load wlan extend vdi failed", __func__);
        return HDF_FAILURE;
    }

    version = HdfGetVdiVersion(g_vdi);
    if (version != VDI_VERSION_ONE) {
        HDF_LOGE("%{public}s: get wlan extend vdi version failed", __func__);
        CloseVdi();
        return HDF_FAILURE;
    }

    struct VdiWrapperWlanExtend *vdiWrapperWlanExtend = NULL;
    vdiWrapperWlanExtend = (struct VdiWrapperWlanExtend *)(g_vdi->vdiBase);
    g_wlanExtendVdiImpl = vdiWrapperWlanExtend->wlanExtendModule;
    if (g_wlanExtendVdiImpl == NULL) {
        HDF_LOGE("%{public}s: get vibrator impl failed", __func__);
        CloseVdi();
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t WlanInterfaceStartChannelMeas(struct IWlanInterface *self, const char *ifName,
    const struct MeasChannelParam *measChannelParam)
{
    int32_t ret;

    (void)self;
    if (ifName == NULL || measChannelParam == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wlanExtendVdiImpl == NULL) {
        HDF_LOGE("%{public}s g_wlanExtendVdiImpl is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wlanExtendVdiImpl->startChannelMeas(self, ifName, measChannelParam);
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
    if (g_wlanExtendVdiImpl == NULL) {
        HDF_LOGE("%{public}s g_wlanExtendVdiImplis NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wlanExtendVdiImpl->getChannelMeasResult(self, ifName, measChannelResult);
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
    if (g_wlanExtendVdiImpl == NULL) {
        HDF_LOGE("%{public}s g_wlanExtendVdiImpl is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wlanExtendVdiImpl->sendCmdIoctl(self, ifName, cmdId, paramBuf, paramBufLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: send ioctl command failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceGetCoexChannelList(struct IWlanInterface *self, const char *ifName,
    uint8_t *paramBuf, uint32_t *paramBufLen)
{
    int32_t ret;
    HDF_LOGI("%{public}s enter WlanInterfaceGetCoexChannelList", __func__);
    (void)self;
    if (ifName == NULL || paramBuf == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wlanExtendVdiImpl == NULL) {
        HDF_LOGE("%{public}s g_wlanExtendVdiImpl is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wlanExtendVdiImpl->getCoexChannelList(self, ifName, paramBuf, paramBufLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get coex channellist failed!, error code: %{public}d", __func__, ret);
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
    if (g_wlanExtendVdiImpl == NULL) {
        HDF_LOGE("%{public}s g_wlanExtendVdiImpl is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wlanExtendVdiImpl->registerHid2dCallback(func, ifName);
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
    if (g_wlanExtendVdiImpl == NULL) {
        HDF_LOGE("%{public}s g_wlanExtendVdiImpl is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wlanExtendVdiImpl->unregisterHid2dCallback(func, ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Unregister hid2d callback failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanExtendInterfaceWifiConstruct(void)
{
    if (g_wlanExtendVdiImpl != NULL) {
        HDF_LOGI("%{public}s wlanExtendVdiImpl is not NULL!", __func__);
        return HDF_SUCCESS;
    }

    int32_t ret;
    ret = InitWlanExtendVdiImpl();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s construct WiFi failed! error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    if (g_wlanExtendVdiImpl == NULL) {
        HDF_LOGE("%{public}s wlanExtendVdiImpl init failed!", __func__);
        CloseVdi();
        return HDF_FAILURE;
    }
    ret = g_wlanExtendVdiImpl->wifiConstruct();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s construct WiFi failed! error code: %{public}d", __func__, ret);
        CloseVdi();
    }
    return ret;
}

int32_t WlanExtendInterfaceWifiDestruct(void)
{
    if (g_wlanExtendVdiImpl == NULL) {
        HDF_LOGI("%{public}s wlanExtendVdiImpl is NULL!", __func__);
        return HDF_SUCCESS;
    }

    int32_t ret;
    ret = g_wlanExtendVdiImpl->wifiDestruct();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s destruct WiFi failed! error code: %{public}d", __func__, ret);
    }
    CloseVdi();
    g_wlanExtendVdiImpl = NULL;
    return ret;
}
