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
#include "v1_0/iwlan_callback.h"
#include "v1_0/iwlan_interface.h"
#include "wlan_common_cmd.h"
#include "wlan_extend_cmd.h"
#include "wlan_impl.h"
#include "v1_0/wlan_interface_service.h"

struct WlanInterfaceService *WlanInterfaceServiceGet(void)
{
    struct WlanInterfaceService *service =
        (struct WlanInterfaceService *)OsalMemCalloc(sizeof(struct WlanInterfaceService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc WlanInterfaceService obj failed!", __func__);
        return NULL;
    }

    if (!WlanInterfaceStubConstruct(&service->stub)) {
        HDF_LOGE("%{public}s: construct WlanInterfaceStub obj failed!", __func__);
        OsalMemFree(service);
        return NULL;
    }

    service->stub.interface.Start = WlanInterfaceStart;
    service->stub.interface.Stop = WlanInterfaceStop;
    service->stub.interface.CreateFeature = WlanInterfaceCreateFeature;
    service->stub.interface.DestroyFeature = WlanInterfaceDestroyFeature;
    service->stub.interface.GetAsscociatedStas = WlanInterfaceGetAsscociatedStas;
    service->stub.interface.GetChipId = WlanInterfaceGetChipId;
    service->stub.interface.GetDeviceMacAddress = WlanInterfaceGetDeviceMacAddress;
    service->stub.interface.GetFeatureByIfName = WlanInterfaceGetFeatureByIfName;
    service->stub.interface.GetFeatureType = WlanInterfaceGetFeatureType;
    service->stub.interface.GetFreqsWithBand = WlanInterfaceGetFreqsWithBand;
    service->stub.interface.GetIfNamesByChipId = WlanInterfaceGetIfNamesByChipId;
    service->stub.interface.GetNetworkIfaceName = WlanInterfaceGetNetworkIfaceName;
    service->stub.interface.GetSupportCombo = WlanInterfaceGetSupportCombo;
    service->stub.interface.GetSupportFeature = WlanInterfaceGetSupportFeature;
    service->stub.interface.RegisterEventCallback = WlanInterfaceRegisterEventCallback;
    service->stub.interface.UnregisterEventCallback = WlanInterfaceUnregisterEventCallback;
    service->stub.interface.ResetDriver = WlanInterfaceResetDriver;
    service->stub.interface.SetCountryCode = WlanInterfaceSetCountryCode;
    service->stub.interface.SetMacAddress = WlanInterfaceSetMacAddress;
    service->stub.interface.SetScanningMacAddress = WlanInterfaceSetScanningMacAddress;
    service->stub.interface.SetTxPower = WlanInterfaceSetTxPower;
    service->stub.interface.GetNetDevInfo = WlanInterfaceGetNetDevInfo;
    service->stub.interface.StartScan = WlanInterfaceStartScan;
    service->stub.interface.GetPowerMode = WlanInterfaceGetPowerMode;
    service->stub.interface.SetPowerMode = WlanInterfaceSetPowerMode;
    service->stub.interface.StartChannelMeas = WlanInterfaceStartChannelMeas;
    service->stub.interface.GetChannelMeasResult = WlanInterfaceGetChannelMeasResult;
    return service;
}

int32_t WlanInterfaceServiceInit(void)
{
    int32_t ret;
    ret = WlanInterfaceWifiConstruct();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s construct wifi interface failed! error code: %{public}d", __func__, ret);
        return ret;
    }
    ret = WlanExtendInterfaceWifiConstruct();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s construct wifi extend interface failed! error code: %{public}d", __func__, ret);
        return ret;
    }
    return ret;
}

void WlanInterfaceServiceRelease(struct WlanInterfaceService *instance)
{
    if (instance != NULL) {
        OsalMemFree(instance);
    }
    if (WlanInterfaceWifiDestruct() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s destruct WiFi failed!", __func__);
    }
    if (WlanExtendInterfaceWifiDestruct() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s wifi extend interface destruct failed!", __func__);
    }
}