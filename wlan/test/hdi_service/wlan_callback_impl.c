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

#include "wlan_callback_impl.h"
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_mem.h>

struct WlanCallbackService {
    struct WlanCallbackStub stub;
};

int32_t WlanCallbackResetDriver(struct IWlanCallback *self, uint32_t event, int32_t code, const char *ifName)
{
    (void)self;
    HDF_LOGE("WlanCallbackResetDriver: receive resetStatus=%{public}d \n", code);
    return HDF_SUCCESS;
}

int32_t WlanCallbackScanResult(
    struct IWlanCallback *self, uint32_t event, const struct HdfWifiScanResult *scanResult, const char *ifName)
{
    (void)self;
    if (scanResult == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("HdiProcessScanResult: flags=%{public}d, caps=%{public}d, freq=%{public}d, beaconInt=%{public}d \n",
        scanResult->flags, scanResult->caps, scanResult->freq, scanResult->beaconInt);
    HDF_LOGE("HdiProcessScanResult: qual=%{public}d, beaconIeLen=%{public}d, level=%{public}d\n", scanResult->qual,
        scanResult->beaconIeLen, scanResult->level);
    HDF_LOGE("HdiProcessScanResult: age=%{public}d, ieLen=%{public}d\n", scanResult->age, scanResult->ieLen);
    return HDF_SUCCESS;
}

struct IWlanCallback *WlanCallbackServiceGet(void)
{
    struct WlanCallbackService *service =
        (struct WlanCallbackService *)OsalMemCalloc(sizeof(struct WlanCallbackService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc WlanCallbackService obj failed!", __func__);
        return NULL;
    }

    if (!WlanCallbackStubConstruct(&service->stub)) {
        HDF_LOGE("%{public}s: construct WlanCallbackStub obj failed!", __func__);
        OsalMemFree(service);
        return NULL;
    }

    service->stub.interface.ResetDriverResult = WlanCallbackResetDriver;
    service->stub.interface.ScanResult = WlanCallbackScanResult;
    return &service->stub.interface;
}

void WlanCallbackServiceRelease(struct IWlanCallback *instance)
{
    struct WlanCallbackService *service = (struct WlanCallbackService *)instance;
    if (service == NULL) {
        return;
    }

    WlanCallbackStubRelease(&service->stub);
    OsalMemFree(service);
}
