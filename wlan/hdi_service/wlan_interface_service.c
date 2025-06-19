/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "v1_3/iwlan_callback.h"
#include "v1_3/iwlan_interface.h"
#include "wlan_common_cmd.h"
#include "wlan_extend_cmd.h"
#include "wlan_impl.h"

struct WlanInterfaceService {
    struct IWlanInterface interface;
};

struct IWlanInterface *WlanInterfaceImplGetInstance(void)
{
    struct WlanInterfaceService *service = (struct WlanInterfaceService *)OsalMemCalloc(
        sizeof(struct WlanInterfaceService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc WlanInterfaceService obj failed!", __func__);
        return NULL;
    }

    service->interface.Start = WlanInterfaceStart;
    service->interface.Stop = WlanInterfaceStop;
    service->interface.CreateFeature = WlanInterfaceCreateFeature;
    service->interface.DestroyFeature = WlanInterfaceDestroyFeature;
    service->interface.GetAssociatedStas = WlanInterfaceGetAssociatedStas;
    service->interface.GetChipId = WlanInterfaceGetChipId;
    service->interface.GetDeviceMacAddress = WlanInterfaceGetDeviceMacAddress;
    service->interface.GetFeatureByIfName = WlanInterfaceGetFeatureByIfName;
    service->interface.GetFeatureType = WlanInterfaceGetFeatureType;
    service->interface.GetFreqsWithBand = WlanInterfaceGetFreqsWithBand;
    service->interface.GetIfNamesByChipId = WlanInterfaceGetIfNamesByChipId;
    service->interface.GetNetworkIfaceName = WlanInterfaceGetNetworkIfaceName;
    service->interface.GetSupportCombo = WlanInterfaceGetSupportCombo;
    service->interface.GetSupportFeature = WlanInterfaceGetSupportFeature;
    service->interface.RegisterEventCallback = WlanInterfaceRegisterEventCallback;
    service->interface.UnregisterEventCallback = WlanInterfaceUnregisterEventCallback;
    service->interface.ResetDriver = WlanInterfaceResetDriver;
    service->interface.SetCountryCode = WlanInterfaceSetCountryCode;
    service->interface.SetMacAddress = WlanInterfaceSetMacAddress;
    service->interface.SetScanningMacAddress = WlanInterfaceSetScanningMacAddress;
    service->interface.SetTxPower = WlanInterfaceSetTxPower;
    service->interface.GetNetDevInfo = WlanInterfaceGetNetDevInfo;
    service->interface.StartScan = WlanInterfaceStartScan;
    service->interface.GetPowerMode = WlanInterfaceGetPowerMode;
    service->interface.SetPowerMode = WlanInterfaceSetPowerMode;
    service->interface.StartChannelMeas = WlanInterfaceStartChannelMeas;
    service->interface.GetChannelMeasResult = WlanInterfaceGetChannelMeasResult;
    service->interface.SetProjectionScreenParam = WlanInterfaceSetProjectionScreenParam;
    service->interface.WifiSendCmdIoctl = WlanInterfaceWifiSendCmdIoctl;
    service->interface.GetStaInfo = WlanInterfaceGetStaInfo;
    service->interface.StartPnoScan = WlanInterfaceStartPnoScan;
    service->interface.StopPnoScan = WlanInterfaceStopPnoScan;
    service->interface.GetSignalPollInfo = WlanInterfaceGetSignalPollInfo;
    service->interface.GetApBandwidth = WlanInterfaceGetApBandwidth;
    service->interface.ResetToFactoryMacAddress = WlanInterfaceResetToFactoryMacAddress;
    service->interface.SendActionFrame = WlanInterfaceSendActionFrame;
    service->interface.RegisterActionFrameReceiver = WlanInterfaceRegisterActionFrameReceiver;
    service->interface.GetCoexictenceChannelList = WlanInterfaceGetCoexChannelList;
    service->interface.SetPowerSaveMode = WlanInterfaceSetPowerSaveMode;
    service->interface.SetDpiMarkRule = WlanInterfaceSetDpiMarkRule;
    service->interface.GetVersion = WlanGetVersion;
    return &service->interface;
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

void WlanInterfaceImplRelease(struct IWlanInterface *instance)
{
    if (instance == NULL) {
        return;
    }
    OsalMemFree(instance);
    if (WlanInterfaceWifiDestruct() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s destruct WiFi failed!", __func__);
    }
    if (WlanExtendInterfaceWifiDestruct() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s wifi extend interface destruct failed!", __func__);
    }
}
